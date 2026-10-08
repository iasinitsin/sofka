use super::*;

/// This test binary, rerun for one test with `KUBECONFIG` set and without
/// proxy or kube-rs debug overrides from the environment.
fn isolated_child(test: &str, kubeconfig: &std::path::Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture"])
        .env("KUBECONFIG", kubeconfig);
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "KUBE_RS_DEBUG_OVERRIDE_URL",
        "KUBE_RS_DEBUG_IMPERSONATE_USER",
        "KUBE_RS_DEBUG_IMPERSONATE_GROUP",
    ] {
        command.env_remove(name);
    }
    command
}

#[tokio::test]
async fn wrapped_kubeconfig_reaches_discovery_on_startup_and_context_selection() {
    const CHILD: &str = "SOFKA_TEST_WRAPPED_KUBECONFIG";
    if let Ok(phase) = std::env::var(CHILD) {
        let error = if phase == "startup" {
            Cluster::connect(false, false)
                .await
                .err()
                .unwrap()
                .to_string()
        } else {
            let (mut app, mut rx) = test_app();
            app.cluster.connected = false;
            app.start_context_picker(None);
            app.handle_msg(Msg::Contexts {
                generation: app.generation,
                list: vec!["target".into()],
            });
            app.handle_key(press(KeyCode::Enter)).unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Msg::ContextSwitched { result, .. } = rx.recv().await.unwrap() {
                        break result.err().unwrap().message;
                    }
                }
            })
            .await
            .unwrap()
        };
        assert!(error.contains("running API discovery"), "{error}");
        return;
    }
    let directory =
        std::env::temp_dir().join(format!("sofka-wrapped-kubeconfig-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("kubeconfig");
    for binary in [false, true] {
        for wrapped in [false, true] {
            std::fs::write(&path, crate::k8s::kubeconfig::fixture(binary, wrapped)).unwrap();
            for phase in ["startup", "context"] {
                let mut command = isolated_child(
                    "app::tests::kubeconfig::wrapped_kubeconfig_reaches_discovery_on_startup_and_context_selection",
                    &path,
                );
                command.env(CHILD, phase);
                let output = tokio::time::timeout(Duration::from_secs(15), command.output())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "binary={binary}, wrapped={wrapped}, phase={phase}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn plugin_reload_reads_the_changed_kubeconfig_file() {
    const CHILD: &str = "SOFKA_TEST_PLUGIN_KUBECONFIG";
    if let Ok(directory) = std::env::var(CHILD) {
        let directory = std::path::Path::new(&directory);
        let config = |name| {
            format!(
                "apiVersion: v1
kind: Config
contexts:
- name: {name}
  context:
    cluster: example
    user: example
current-context: {name}
"
            )
        };
        let path = directory.join("config");
        let replacement = directory.join("replacement");
        std::fs::write(&path, config("before")).unwrap();
        std::fs::write(&replacement, config("after")).unwrap();
        let (mut app, mut rx) = test_app();
        let context = app.cluster.context.clone();
        let mut plugin = kubeconfig_reload_plugin();
        let report = plugin.args[0].clone();
        plugin.command = "/bin/sh".into();
        plugin.args = vec![
            "-c".into(),
            r#"cp "$1" "$2" && printf '%s' "$3""#.into(),
            "reload-test".into(),
            replacement.to_str().unwrap().into(),
            path.to_str().unwrap().into(),
            report,
        ];
        app.plugins = vec![plugin];
        plugin_command(&mut app, "example-plugin");
        app.handle_msg(plugin_result(&mut rx).await);
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = rx.recv().await.unwrap();
                if matches!(msg, Msg::Contexts { .. } | Msg::Error { .. }) {
                    break msg;
                }
            }
        })
        .await
        .unwrap();
        app.handle_msg(result);
        assert_eq!(app.mode, Mode::Contexts);
        assert_eq!(app.ctx_list, ["after"]);
        assert_eq!(app.cluster.context, context);
        return;
    }
    let directory =
        std::env::temp_dir().join(format!("sofka-plugin-kubeconfig-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "app::tests::kubeconfig::plugin_reload_reads_the_changed_kubeconfig_file",
            "--nocapture",
        ])
        .env(CHILD, &directory)
        .env("KUBECONFIG", directory.join("config"))
        .output()
        .await
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An expired `auth-provider: oidc` id-token is refreshed when the view
/// loads, and the rotated tokens land in the kubeconfig, so a kubectl that
/// shares the file does not send the refresh token sofka already spent.
#[tokio::test]
async fn refresh_key_saves_rotated_oidc_tokens_to_the_kubeconfig() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const CHILD: &str = "SOFKA_TEST_OIDC_KUBECONFIG";
    let Ok(path) = std::env::var(CHILD) else {
        let directory =
            std::env::temp_dir().join(format!("sofka-oidc-kubeconfig-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("config");
        let mut command = isolated_child(
            "app::tests::kubeconfig::refresh_key_saves_rotated_oidc_tokens_to_the_kubeconfig",
            &path,
        );
        command.env(CHILD, &path);
        let output = tokio::time::timeout(Duration::from_secs(30), command.output())
            .await
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    };

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        let head = String::from_utf8(request).unwrap();
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        head + &String::from_utf8(body).unwrap()
    }

    let issued = crate::k8s::oidc::test_token(4_070_908_800);
    let dex = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", dex.local_addr().unwrap());
    let (grant_tx, mut grants) = mpsc::unbounded_channel();
    let dex_issuer = issuer.clone();
    let dex_token = issued.clone();
    let dex_server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = dex.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            let body = if request.starts_with("GET /.well-known/openid-configuration ") {
                json!({ "token_endpoint": format!("{dex_issuer}/token") }).to_string()
            } else {
                grant_tx.send(request).unwrap();
                json!({ "id_token": dex_token, "refresh_token": "refresh-2" }).to_string()
            };
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });

    let api = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = format!("http://{}", api.local_addr().unwrap());
    let (request_tx, mut requests) = mpsc::unbounded_channel();
    let api_server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = api.accept().await.unwrap();
            let request_tx = request_tx.clone();
            tokio::spawn(async move {
                let request = read_request(&mut stream).await;
                if !request.lines().next().unwrap().contains("/pods?") {
                    let _ = stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
                request_tx.send(request).unwrap();
                let body = concat!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                    "{\"type\":\"ADDED\",\"object\":{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"oidc-pod\",\"namespace\":\"default\",\"resourceVersion\":\"1\"}}}\n",
                    "{\"type\":\"BOOKMARK\",\"object\":{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"resourceVersion\":\"1\",\"annotations\":{\"k8s.io/initial-events-end\":\"true\"}}}}\n",
                );
                stream.write_all(body.as_bytes()).await.unwrap();
                std::future::pending::<()>().await;
            });
        }
    });

    let expired = crate::k8s::oidc::test_token(1);
    std::fs::write(
        &path,
        format!(
            "apiVersion: v1
kind: Config
current-context: dex
clusters:
- name: dex
  cluster:
    server: {server}
contexts:
- name: dex
  context:
    cluster: dex
    user: dex
users:
- name: dex
  user:
    auth-provider:
      name: oidc
      config:
        idp-issuer-url: {issuer}
        client-id: kubernetes
        client-secret: secret
        id-token: {expired}
        refresh-token: refresh-1
"
        ),
    )
    .unwrap();
    let config = crate::k8s::kubeconfig::infer().await.unwrap();

    let (mut app, mut rx) = test_app();
    app.cluster.client = crate::k8s::build_client(config, false, false).unwrap();
    app.kind = app.cluster.resolve("pods");
    app.kind_plural = "pods".into();
    app.handle_key(press(KeyCode::Char('r'))).unwrap();
    sync_selector_view(&mut app, &mut rx).await;
    assert_eq!(row_names(&app), ["oidc-pod"]);

    let grant = grants.recv().await.unwrap();
    assert!(grant.ends_with("refresh_token=refresh-1"), "{grant}");
    let request = requests.recv().await.unwrap();
    assert!(
        request.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("authorization")
                    && value.trim() == format!("Bearer {issued}")
            })
        }),
        "{request}"
    );
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("refresh-token: refresh-2"), "{saved}");
    assert!(saved.contains(&format!("id-token: {issued}")), "{saved}");

    app.handle_key(press(KeyCode::Char('q'))).unwrap();
    dex_server.abort();
    api_server.abort();
}
