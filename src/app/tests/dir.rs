use super::*;
use crate::app::dir::{
    DirEntryKind, DirPlan, DirVerb, RenderedObject, manifest_source, manifest_summary,
    preview_lines, rendered_objects, resolve_dir_arg,
};
use std::path::{Path, PathBuf};

const DIFF: &str = "\
diff -u -N /tmp/LIVE-1/v1.ConfigMap.default.web /tmp/MERGED-2/v1.ConfigMap.default.web
--- /tmp/LIVE-1/v1.ConfigMap.default.web\t2026-10-16
+++ /tmp/MERGED-2/v1.ConfigMap.default.web\t2026-10-16
@@ -1,3 +1,3 @@
-  hello: world
+  hello: there
";

/// A scratch tree, removed on drop: `app/` (plain), `kust/` (kustomization),
/// `web.yaml`, plus a hidden manifest and a README the browser must skip.
struct Tree(PathBuf);

impl std::ops::Deref for Tree {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn manifests() -> Tree {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "sofka-dir-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(root.join("app")).unwrap();
    std::fs::create_dir_all(root.join("kust")).unwrap();
    std::fs::write(root.join("kust/kustomization.yaml"), "resources: []\n").unwrap();
    std::fs::write(root.join("app/cm.yml"), "kind: ConfigMap\n").unwrap();
    std::fs::write(
        root.join("web.yaml"),
        "kind: ConfigMap\nmetadata:\n  name: web\n",
    )
    .unwrap();
    std::fs::write(root.join(".hidden.yaml"), "").unwrap();
    std::fs::write(root.join("README.md"), "").unwrap();
    Tree(std::fs::canonicalize(root).unwrap())
}

fn type_command(app: &mut App, cmd: &str) {
    app.handle_key(press(KeyCode::Char(':'))).unwrap();
    for c in cmd.chars() {
        app.handle_key(press(KeyCode::Char(c))).unwrap();
    }
    app.handle_key(press(KeyCode::Enter)).unwrap();
}

fn names(app: &App) -> Vec<(&str, DirEntryKind)> {
    app.dir
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.kind))
        .collect()
}

fn select(app: &mut App, name: &str) {
    app.handle_key(press(KeyCode::Char('g'))).unwrap();
    while app.dir.entries[app.dir.state.selected().unwrap()].name != name {
        app.handle_key(press(KeyCode::Char('j'))).unwrap();
    }
}

#[tokio::test]
async fn dir_lists_folders_first_and_only_manifests() {
    let root = manifests();
    let (mut app, _rx) = test_app();
    type_command(&mut app, &format!("dir {}", root.display()));

    assert_eq!(app.mode, Mode::Dir);
    assert_eq!(app.dir.path, root.0);
    assert_eq!(
        names(&app),
        [
            ("app", DirEntryKind::Dir),
            ("kust", DirEntryKind::Kustomization),
            ("web.yaml", DirEntryKind::Manifest),
        ]
    );
}

#[tokio::test]
async fn dir_enters_folders_and_backspace_returns_to_the_folder_left() {
    let root = manifests();
    let (mut app, _rx) = test_app();
    type_command(&mut app, &format!("dir {}", root.display()));

    select(&mut app, "app");
    app.handle_key(press(KeyCode::Enter)).unwrap();
    assert_eq!(app.dir.path, root.join("app"));
    assert_eq!(names(&app), [("cm.yml", DirEntryKind::Manifest)]);

    app.handle_key(press(KeyCode::Backspace)).unwrap();
    assert_eq!(app.dir.path, root.0);
    assert_eq!(app.dir.state.selected(), Some(0));

    app.handle_key(press(KeyCode::Esc)).unwrap();
    assert_eq!(app.mode, Mode::Table);
}

#[tokio::test]
async fn dir_enter_on_a_manifest_shows_it_and_esc_returns_to_the_listing() {
    let root = manifests();
    let (mut app, _rx) = test_app();
    type_command(&mut app, &format!("dir {}", root.display()));

    select(&mut app, "web.yaml");
    app.handle_key(press(KeyCode::Enter)).unwrap();
    assert_eq!(app.mode, Mode::Detail);
    assert!(app.detail.lines.iter().any(|l| l == "  name: web"));

    app.handle_key(press(KeyCode::Esc)).unwrap();
    assert_eq!(app.mode, Mode::Dir);
}

#[tokio::test]
async fn dir_rejects_a_path_that_is_not_a_directory() {
    let root = manifests();
    let (mut app, _rx) = test_app();
    type_command(
        &mut app,
        &format!("dir {}", root.join("web.yaml").display()),
    );
    assert_eq!(app.mode, Mode::Table);
    assert!(app.flash.contains("not a directory"), "{}", app.flash);
}

fn configmap(name: &str, ns: &str) -> serde_json::Value {
    json!({"apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": ns}, "data": {"hello": "there"}})
}

/// What the off-thread render of `path` would hand back: `objects` written to
/// a private snapshot, plus a diff for an apply.
fn plan(path: PathBuf, objects: &[serde_json::Value], diff: Option<&str>) -> DirPlan {
    DirPlan {
        path,
        snapshot: json!({"apiVersion": "v1", "kind": "List", "items": objects}).to_string(),
        objects: objects
            .iter()
            .map(|o| RenderedObject {
                api_version: o["apiVersion"].as_str().unwrap().into(),
                kind: o["kind"].as_str().unwrap().into(),
                name: o["metadata"]["name"].as_str().unwrap().into(),
                namespace: o["metadata"]["namespace"].as_str().unwrap_or("").into(),
            })
            .collect(),
        diff: diff.map(String::from),
    }
}

fn deliver(app: &mut App, request: u64, verb: DirVerb, plan: DirPlan) {
    app.handle_msg(Msg::DirPlan {
        generation: app.generation,
        claim: current_claim(app),
        request,
        verb,
        path: plan.path.clone(),
        result: Box::new(Ok(plan)),
    });
}

/// Open the browser on `web.yaml` and press `key`, returning the request the
/// render was started under.
fn start(root: &Path, key: KeyEvent) -> (App, Receiver<Msg>, u64) {
    let (mut app, rx) = test_app();
    app.cluster
        .register_kind("", "ConfigMap", "configmaps", true);
    type_command(&mut app, &format!("dir {}", root.display()));
    select(&mut app, "web.yaml");
    app.handle_key(key).unwrap();
    let request = app.dir.request;
    (app, rx, request)
}

#[tokio::test]
async fn dir_apply_previews_the_diff_then_confirms_the_snapshot() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('a')));
    assert_eq!(app.mode, Mode::Dir);
    assert!(app.flash.starts_with("diffing"), "{}", app.flash);

    let web = root.join("web.yaml");
    deliver(
        &mut app,
        request,
        DirVerb::Apply,
        plan(web.clone(), &[configmap("web", "default")], Some(DIFF)),
    );
    assert_eq!(app.mode, Mode::Diff);
    assert_eq!(app.detail.lines[0], "── v1.ConfigMap.default.web");
    assert!(!app.detail.lines.iter().any(|l| l.starts_with("+++")));

    // Editing the source after the preview changes nothing: the confirmed
    // action carries the rendered snapshot, not the path.
    std::fs::write(&web, "kind: ConfigMap\nmetadata:\n  name: other\n").unwrap();
    app.handle_key(press(KeyCode::Char('a'))).unwrap();
    assert_eq!(app.mode, Mode::Confirm);
    assert!(
        app.confirm_label.starts_with("Apply "),
        "{}",
        app.confirm_label
    );
    assert!(
        app.confirm_label.contains("(1 object)"),
        "{}",
        app.confirm_label
    );
    match &app.confirm_action {
        Some(ConfirmAction::Manifest {
            verb: DirVerb::Apply,
            plan,
        }) => {
            assert!(plan.snapshot.contains("\"web\""), "{}", plan.snapshot);
            assert!(!plan.snapshot.contains("other"), "{}", plan.snapshot);
        }
        _ => panic!("expected a manifest apply"),
    }

    app.handle_key(press(KeyCode::Esc)).unwrap();
    assert_eq!(app.mode, Mode::Dir);
    assert!(app.confirm_action.is_none());
}

#[tokio::test]
async fn dir_apply_with_no_changes_stays_in_the_listing() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('a')));
    deliver(
        &mut app,
        request,
        DirVerb::Apply,
        plan(
            root.join("web.yaml"),
            &[configmap("web", "default")],
            Some(""),
        ),
    );
    assert_eq!(app.mode, Mode::Dir);
    assert!(app.flash.starts_with("no changes"), "{}", app.flash);
}

#[tokio::test]
async fn dir_drops_a_diff_for_an_earlier_selection() {
    let root = manifests();
    let (mut app, _rx, first) = start(&root, press(KeyCode::Char('a')));

    // Another row is diffed before the first result lands.
    select(&mut app, "kust");
    app.handle_key(press(KeyCode::Char('a'))).unwrap();
    let second = app.dir.request;
    assert_ne!(first, second);

    deliver(
        &mut app,
        first,
        DirVerb::Apply,
        plan(
            root.join("web.yaml"),
            &[configmap("web", "default")],
            Some(DIFF),
        ),
    );
    assert_eq!(app.mode, Mode::Dir);
    assert!(app.dir.preview.is_none());

    deliver(
        &mut app,
        second,
        DirVerb::Apply,
        plan(
            root.join("kust"),
            &[configmap("kust", "default")],
            Some(DIFF),
        ),
    );
    assert_eq!(app.mode, Mode::Diff);
    assert_eq!(
        app.dir.preview.as_ref().map(|p| p.path.clone()),
        Some(root.join("kust"))
    );
}

#[tokio::test]
async fn dir_leaving_the_preview_drops_the_pending_apply() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('a')));
    deliver(
        &mut app,
        request,
        DirVerb::Apply,
        plan(
            root.join("web.yaml"),
            &[configmap("web", "default")],
            Some(DIFF),
        ),
    );

    app.handle_key(press(KeyCode::Esc)).unwrap();
    assert_eq!(app.mode, Mode::Dir);
    assert!(app.dir.preview.is_none());

    // `a` in a diff that did not come from the browser applies nothing.
    app.mode = Mode::Diff;
    app.return_mode = Mode::Table;
    app.handle_key(press(KeyCode::Char('a'))).unwrap();
    assert_eq!(app.mode, Mode::Diff);
    assert!(app.confirm_action.is_none());
}

#[tokio::test]
async fn dir_palette_navigation_drops_an_open_preview() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('a')));
    deliver(
        &mut app,
        request,
        DirVerb::Apply,
        plan(
            root.join("web.yaml"),
            &[configmap("web", "default")],
            Some(DIFF),
        ),
    );
    assert!(app.dir.preview.is_some());

    // A palette visit that returns to the diff keeps it.
    app.handle_key(press(KeyCode::Char(':'))).unwrap();
    assert!(app.dir.preview.is_some());
    app.handle_key(press(KeyCode::Esc)).unwrap();
    assert_eq!(app.mode, Mode::Diff);
    assert!(app.dir.preview.is_some());

    // Help over the diff, and a search inside that help, also return to it.
    app.handle_key(press(KeyCode::Char('?'))).unwrap();
    app.handle_key(press(KeyCode::Char('/'))).unwrap();
    assert!(app.dir.preview.is_some());
    app.handle_key(press(KeyCode::Esc)).unwrap();
    app.handle_key(press(KeyCode::Esc)).unwrap();
    assert_eq!(app.mode, Mode::Diff);
    assert!(app.dir.preview.is_some());

    type_command(&mut app, "pods");
    assert_ne!(app.mode, Mode::Diff);
    assert!(app.dir.preview.is_none());
}

#[tokio::test]
async fn dir_bulk_limit_counts_every_kind_in_the_selection() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('d')));
    guardrail(
        &mut app,
        r#"
        [[guardrails]]
        actions = ["delete"]
        max_bulk = 1
        "#,
    );
    let deployment = json!({"apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "default"}});
    deliver(
        &mut app,
        request,
        DirVerb::Delete,
        plan(
            root.join("web.yaml"),
            &[configmap("web", "default"), deployment],
            None,
        ),
    );
    assert!(app.confirm_action.is_none());
    assert!(app.flash.contains("exceeds the max of 1"), "{}", app.flash);
}

#[cfg(unix)]
#[tokio::test]
async fn dir_opens_a_manifest_whose_name_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt;
    let root = manifests();
    let name = std::ffi::OsStr::from_bytes(b"b\xffad.yaml");
    if std::fs::write(root.join(name), "kind: ConfigMap\n").is_err() {
        // Some filesystems (APFS) refuse non-UTF-8 names outright.
        return;
    }
    let (mut app, _rx) = test_app();
    type_command(&mut app, &format!("dir {}", root.display()));
    let lossy = name.to_string_lossy().into_owned();
    select(&mut app, &lossy);
    app.handle_key(press(KeyCode::Enter)).unwrap();
    assert_eq!(app.mode, Mode::Detail);
    assert_eq!(app.detail.lines[0], "kind: ConfigMap");
}

#[tokio::test]
async fn dir_delete_confirms_every_rendered_object() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('d')));
    assert_eq!(app.mode, Mode::Dir);

    deliver(
        &mut app,
        request,
        DirVerb::Delete,
        plan(
            root.join("web.yaml"),
            &[configmap("a", "default"), configmap("b", "default")],
            None,
        ),
    );
    assert_eq!(app.mode, Mode::Confirm);
    assert!(
        app.confirm_label.starts_with("Delete the 2 objects in "),
        "{}",
        app.confirm_label
    );
    assert!(matches!(
        app.confirm_action,
        Some(ConfirmAction::Manifest {
            verb: DirVerb::Delete,
            ..
        })
    ));
    app.handle_key(press(KeyCode::Esc)).unwrap();
    assert_eq!(app.mode, Mode::Dir);
}

#[tokio::test]
async fn dir_readonly_blocks_apply_and_delete() {
    let root = manifests();
    let (mut app, _rx) = test_app();
    app.readonly = true;
    type_command(&mut app, &format!("dir {}", root.display()));
    select(&mut app, "web.yaml");

    app.handle_key(press(KeyCode::Char('a'))).unwrap();
    assert!(app.flash.starts_with("read-only"), "{}", app.flash);
    app.handle_key(press(KeyCode::Char('d'))).unwrap();
    assert!(app.flash.starts_with("read-only"), "{}", app.flash);
    assert_eq!(app.mode, Mode::Dir);
}

fn guardrail(app: &mut App, toml: &str) {
    app.guardrails = toml::from_str::<crate::config::Config>(toml)
        .unwrap()
        .guardrails;
}

#[tokio::test]
async fn dir_namespace_guardrails_match_the_rendered_objects() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('d')));
    guardrail(
        &mut app,
        r#"
        [[guardrails]]
        actions = ["delete"]
        resources = ["configmaps"]
        namespaces = ["prod"]
        deny = true
        "#,
    );
    deliver(
        &mut app,
        request,
        DirVerb::Delete,
        plan(
            root.join("web.yaml"),
            &[configmap("a", "dev"), configmap("b", "prod")],
            None,
        ),
    );
    assert!(app.confirm_action.is_none());
    assert!(app.flash.contains("blocked by guardrail"), "{}", app.flash);
}

#[tokio::test]
async fn dir_guardrail_confirmation_applies_to_apply() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('a')));
    guardrail(
        &mut app,
        r#"
        [[guardrails]]
        actions = ["apply"]
        namespaces = ["prod"]
        confirmation = "type-resource-name"
        "#,
    );
    deliver(
        &mut app,
        request,
        DirVerb::Apply,
        plan(
            root.join("web.yaml"),
            &[configmap("web", "prod")],
            Some(DIFF),
        ),
    );
    app.handle_key(press(KeyCode::Char('a'))).unwrap();
    assert_eq!(app.mode, Mode::Prompt);
    assert!(app.prompt_label.contains("'web'"), "{}", app.prompt_label);
    app.handle_key(press(KeyCode::Esc)).unwrap();
    assert_eq!(app.mode, Mode::Dir);
}

#[tokio::test]
async fn dir_refuses_a_kind_it_cannot_match_against_guardrails() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('d')));
    let policy = json!({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "deny-all", "namespace": "prod"}});
    deliver(
        &mut app,
        request,
        DirVerb::Delete,
        plan(root.join("web.yaml"), &[policy], None),
    );
    assert!(app.confirm_action.is_none());
    assert!(
        app.flash.contains("can't check guardrails"),
        "{}",
        app.flash
    );
    assert!(app.flash.contains("NetworkPolicy"), "{}", app.flash);
}

#[tokio::test]
async fn dir_refuses_a_namespaced_object_rendered_without_a_namespace() {
    let root = manifests();
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('d')));
    let bare = json!({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "web"}});
    deliver(
        &mut app,
        request,
        DirVerb::Delete,
        plan(root.join("web.yaml"), &[bare], None),
    );
    assert!(app.confirm_action.is_none());
    assert!(app.flash.contains("without a namespace"), "{}", app.flash);

    // A cluster-scoped object has none, and that is fine.
    let (mut app, _rx, request) = start(&root, press(KeyCode::Char('d')));
    let ns = json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "web"}});
    deliver(
        &mut app,
        request,
        DirVerb::Delete,
        plan(root.join("web.yaml"), &[ns], None),
    );
    assert_eq!(app.mode, Mode::Confirm);
}

#[cfg(unix)]
#[tokio::test]
async fn dir_skips_a_fifo_with_a_manifest_name() {
    let root = manifests();
    let fifo = std::ffi::CString::new(root.join("pipe.yaml").to_string_lossy().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let (mut app, _rx) = test_app();
    type_command(&mut app, &format!("dir {}", root.display()));
    assert!(!names(&app).iter().any(|(n, _)| *n == "pipe.yaml"));
}

#[test]
fn rendered_objects_unwrap_lists_and_drop_the_last_applied_annotation() {
    let list = json!({"apiVersion": "v1", "kind": "List", "items": [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "a", "namespace": "home",
            "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"}}},
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "zz"}},
    ]});
    let (items, objects) = rendered_objects(&list.to_string()).unwrap();
    assert!(items[0]["metadata"].get("annotations").is_none());
    assert_eq!(objects[0].namespace, "home");
    assert_eq!(objects[1].namespace, "");
    assert_eq!(objects[1].kind, "Namespace");

    let single = json!({"apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "web", "namespace": "x"}});
    let (items, objects) = rendered_objects(&single.to_string()).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(objects[0].api_version, "apps/v1");

    let empty = json!({"apiVersion": "v1", "kind": "List", "items": []});
    assert!(rendered_objects(&empty.to_string()).is_err());
}

#[test]
fn manifest_sources_follow_the_entry_kind() {
    let p = Path::new("/m/x");
    assert_eq!(manifest_source(p, DirEntryKind::Manifest), ["-f", "/m/x"]);
    assert_eq!(manifest_source(p, DirEntryKind::Dir), ["-f", "/m/x", "-R"]);
    assert_eq!(
        manifest_source(p, DirEntryKind::Kustomization),
        ["-k", "/m/x"]
    );
}

#[test]
fn preview_lines_replace_temp_file_headers() {
    assert_eq!(
        preview_lines(DIFF),
        [
            "── v1.ConfigMap.default.web",
            "@@ -1,3 +1,3 @@",
            "-  hello: world",
            "+  hello: there",
        ]
    );
}

#[test]
fn dir_argument_resolves_home_and_relative_paths() {
    let cwd = Path::new("/nonexistent/cwd");
    let home = Path::new("/nonexistent/home");
    assert_eq!(resolve_dir_arg("", cwd, Some(home)), cwd);
    assert_eq!(resolve_dir_arg(" ~ ", cwd, Some(home)), home);
    assert_eq!(resolve_dir_arg("~/k8s", cwd, Some(home)), home.join("k8s"));
    assert_eq!(
        resolve_dir_arg("k8s app", cwd, Some(home)),
        cwd.join("k8s app")
    );
    assert_eq!(resolve_dir_arg("/abs", cwd, Some(home)), Path::new("/abs"));
}

#[test]
fn manifest_summary_names_the_first_object() {
    assert_eq!(
        manifest_summary("apply", "web.yaml", "configmap/web configured\n"),
        "applied web.yaml: configmap/web configured"
    );
    assert_eq!(
        manifest_summary("delete", "k", "a deleted\nb deleted\nc deleted\n"),
        "deleted k: a deleted (+2 more)"
    );
    assert_eq!(
        manifest_summary("apply", "x", ""),
        "applied x: nothing to do"
    );
}

/// The kubectl contract `:dir` relies on, checked against a real cluster with
/// dry runs only: a client-side render fills in the context's default
/// namespace for a namespaced object and leaves a cluster-scoped one empty,
/// and `kubectl diff -f -` reads the rendered `List` from stdin.
/// `SOFKA_TEST_KUBE_CONTEXT=<context> cargo test e2e_dir -- --ignored`
#[tokio::test]
#[ignore]
async fn e2e_dir_render_and_diff_contract() {
    let context =
        std::env::var("SOFKA_TEST_KUBE_CONTEXT").expect("SOFKA_TEST_KUBE_CONTEXT not set");
    let root = manifests();
    let source = root.join("contract.yaml");
    std::fs::write(
        &source,
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: sofka-dir-contract\n---\n\
         apiVersion: v1\nkind: Namespace\nmetadata:\n  name: sofka-dir-contract\n",
    )
    .unwrap();
    let base: Vec<std::ffi::OsString> = ["kubectl", "--context", &context]
        .map(std::ffi::OsString::from)
        .to_vec();
    let plan = crate::app::dir::plan(base, DirVerb::Apply, source, DirEntryKind::Manifest)
        .await
        .expect("render and diff");
    let configmap = plan.objects.iter().find(|o| o.kind == "ConfigMap").unwrap();
    assert!(
        !configmap.namespace.is_empty(),
        "namespace was not defaulted"
    );
    let namespace = plan.objects.iter().find(|o| o.kind == "Namespace").unwrap();
    assert!(namespace.namespace.is_empty());
    let diff = plan.diff.expect("an apply plan carries a diff");
    assert!(diff.contains("sofka-dir-contract"), "{diff}");
}
