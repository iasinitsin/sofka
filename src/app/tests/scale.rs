use super::*;
use std::convert::Infallible;

fn custom_app(namespaced: bool) -> (App, Receiver<Msg>) {
    let (mut app, rx) = test_app();
    app.cluster
        .register_kind("example.com", "TodoApp", "todoapps", namespaced);
    app.switch_kind("todoapps.example.com");
    app.kind.as_mut().unwrap().scalable = true;
    for name in ["a", "b"] {
        let mut value = json!({"apiVersion":"example.com/v1", "kind":"TodoApp",
            "metadata":{"name":name}, "spec":{"size":7,"replicas":99}});
        if namespaced {
            value["metadata"]["namespace"] = json!("default");
        }
        apply(&mut app, value);
    }
    (app, rx)
}

#[tokio::test]
async fn custom_scale_uses_subresource_for_both_scopes_and_reports_errors() {
    for namespaced in [true, false] {
        for forbidden in [false, true] {
            let (mut app, mut rx) = custom_app(namespaced);
            let (sent, mut requests) = mpsc::unbounded_channel();
            app.cluster.client = kube::Client::new(
                tower::service_fn(move |req: http::Request<kube::client::Body>| {
                    let sent = sent.clone();
                    async move {
                        let method = req.method().clone();
                        let uri = req.uri().path().to_string();
                        let content_type =
                            req.headers()["content-type"].to_str().unwrap().to_string();
                        let body: Value =
                            serde_json::from_slice(&req.into_body().collect_bytes().await.unwrap())
                                .unwrap();
                        sent.send((method, uri, content_type, body)).unwrap();
                        let (code, body) = if forbidden {
                            (
                                403,
                                json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","message":"scale denied","code":403}),
                            )
                        } else {
                            (
                                200,
                                json!({"apiVersion":"autoscaling/v1","kind":"Scale","metadata":{"name":"a"},"spec":{"replicas":0}}),
                            )
                        };
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .status(code)
                                .body(http_body_util::Full::new(hyper::body::Bytes::from(
                                    body.to_string(),
                                )))
                                .unwrap(),
                        )
                    }
                }),
                "default",
            );
            app.handle_key(press(KeyCode::Char(' '))).unwrap();
            app.handle_key(press(KeyCode::Down)).unwrap();
            app.handle_key(press(KeyCode::Char(' '))).unwrap();
            app.handle_key(press(KeyCode::Down)).unwrap();
            app.handle_key(press(KeyCode::Char('s'))).unwrap();
            assert_eq!(app.mode, Mode::Prompt);
            assert!(app.prompt_label.contains("Scale 2 todoapps"));
            app.handle_key(press(KeyCode::Char('0'))).unwrap();
            app.handle_key(press(KeyCode::Enter)).unwrap();
            for name in ["a", "b"] {
                let (method, path, content_type, body) =
                    tokio::time::timeout(Duration::from_secs(2), requests.recv())
                        .await
                        .unwrap()
                        .unwrap();
                let scope = if namespaced {
                    "namespaces/default/"
                } else {
                    ""
                };
                assert_eq!(method, http::Method::PATCH);
                assert_eq!(
                    path,
                    format!("/apis/example.com/v1/{scope}todoapps/{name}/scale")
                );
                assert_eq!(content_type, "application/merge-patch+json");
                assert_eq!(body, json!({"spec":{"replicas":0}}));
            }
            loop {
                let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                let done = matches!(msg, Msg::Flash { .. });
                app.handle_msg(msg);
                if done {
                    break;
                }
            }
            assert_eq!(app.flash_err, forbidden);
            assert!(app.flash.contains(if forbidden {
                "scale denied"
            } else {
                "scaled 2 todoapps"
            }));
        }
    }
}

#[tokio::test]
async fn custom_scale_prompt_validation_and_readonly() {
    let (mut app, _rx) = custom_app(true);
    app.handle_key(press(KeyCode::Char('s'))).unwrap();
    assert_eq!(app.prompt_label, "Scale a to replicas:");
    app.handle_key(press(KeyCode::Esc)).unwrap();
    for input in ["-1", "abc", "2147483648"] {
        app.handle_key(press(KeyCode::Char('s'))).unwrap();
        for ch in input.chars() {
            app.handle_key(press(KeyCode::Char(ch))).unwrap();
        }
        app.handle_key(press(KeyCode::Enter)).unwrap();
        assert!(app.flash.contains("invalid replica count"));
    }
    app.readonly = true;
    app.handle_key(press(KeyCode::Char('s'))).unwrap();
    assert_eq!(app.mode, Mode::Table);
    assert!(app.flash.contains("read-only"));
    app.readonly = false;
    app.kind.as_mut().unwrap().scalable = false;
    app.handle_key(press(KeyCode::Char('s'))).unwrap();
    assert_eq!(app.mode, Mode::Table);
    assert!(app.flash.contains("does not support scale"));
}
