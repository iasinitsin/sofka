use super::*;

/// An API server behind a proxy that buffers responses, as nginx does by
/// default. The pods watch is large enough to pass at once. A streaming list
/// of one owner is not, and nothing of it arrives while the stream is open.
/// A plain list is complete and passes. Every request URI is reported.
fn buffering_proxy_api() -> (Cluster, mpsc::UnboundedReceiver<http::Uri>) {
    use futures_util::stream;
    use hyper::body::{Bytes, Frame};
    use std::convert::Infallible;

    let (seen, requests) = mpsc::unbounded_channel();
    let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
        let uri = request.uri().clone();
        seen.send(uri.clone()).ok();
        async move {
            let query: HashMap<_, _> = form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
                .into_owned()
                .collect();
            let owner = |kind: &str, name: &str| json!({"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": format!("{name}-uid"), "controller": true});
            let pods = uri.path() == "/api/v1/namespaces/prod/pods";
            let objects = match uri.path() {
                "/api/v1/namespaces/prod/pods" => vec![
                    json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "web-7d9f-abcde", "namespace": "prod", "uid": "pod-1", "resourceVersion": "10", "ownerReferences": [owner("ReplicaSet", "web-7d9f")]}}),
                    json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "db-0", "namespace": "prod", "uid": "pod-2", "resourceVersion": "10", "ownerReferences": [owner("StatefulSet", "db")]}}),
                ],
                "/apis/apps/v1/namespaces/prod/replicasets" => vec![
                    json!({"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": {"name": "web-7d9f", "namespace": "prod", "uid": "web-7d9f-uid", "resourceVersion": "10"}}),
                    json!({"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": {"name": "web-old", "namespace": "prod", "uid": "web-old-uid", "resourceVersion": "10"}}),
                ],
                "/apis/apps/v1/namespaces/prod/statefulsets" => vec![
                    json!({"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": {"name": "db", "namespace": "prod", "uid": "db-uid", "resourceVersion": "10"}}),
                ],
                _ => Vec::new(),
            };
            let wanted = query
                .get("fieldSelector")
                .and_then(|selector| selector.strip_prefix("metadata.name="))
                .map(str::to_owned);
            let objects: Vec<_> = objects
                .into_iter()
                .filter(|object| {
                    wanted
                        .as_deref()
                        .is_none_or(|name| object["metadata"]["name"] == name)
                })
                .collect();
            let watch = query.get("watch").is_some_and(|value| value == "true");
            let streaming = query.contains_key("sendInitialEvents");
            if watch && (!streaming || !pods) {
                // Held in the proxy's buffer: no response yet.
                std::future::pending::<()>().await;
            }
            let body = if watch {
                let mut lines: Vec<String> = objects
                    .into_iter()
                    .map(|object| json!({"type": "ADDED", "object": object}).to_string())
                    .collect();
                lines.push(json!({"type": "BOOKMARK", "object": {"apiVersion": "v1", "kind": "Pod", "metadata": {"resourceVersion": "10", "annotations": {"k8s.io/initial-events-end": "true"}}}}).to_string());
                lines.join("\n") + "\n"
            } else {
                json!({"apiVersion": "v1", "kind": "List", "metadata": {"resourceVersion": "10"}, "items": objects}).to_string()
            };
            let frames = stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from(body)))]);
            let frames = if watch {
                frames.chain(stream::pending()).boxed()
            } else {
                frames.boxed()
            };
            Ok::<_, Infallible>(http::Response::new(http_body_util::StreamBody::new(frames)))
        }
    });
    let mut cluster = Cluster::fake();
    cluster.register_kind("apps", "ReplicaSet", "replicasets", true);
    cluster.register_kind("apps", "StatefulSet", "statefulsets", true);
    cluster.client = kube::Client::new(service, "default");
    (cluster, requests)
}

/// Shift-J behind a buffering proxy: the owner's streaming list never
/// arrives, so the view falls back to a plain list and shows the owner.
#[tokio::test]
async fn jump_owner_shows_the_owner_behind_a_buffering_proxy() {
    for (pod, owner_plural, owner) in [
        ("web-7d9f-abcde", "replicasets", "web-7d9f"),
        ("db-0", "statefulsets", "db"),
    ] {
        let (cluster, mut requests) = buffering_proxy_api();
        let (mut app, mut rx) = test_app();
        app.cluster = cluster;
        app.switch_kind_ns("pods", Some("prod"));
        sync_selector_view(&mut app, &mut rx).await;
        let index = row_names(&app).iter().position(|name| name == pod).unwrap();
        app.table_state.select(Some(index));
        while requests.try_recv().is_ok() {}

        app.handle_key(press(KeyCode::Char('J'))).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let msg = rx.recv().await.expect("watch channel closed");
                assert!(
                    !matches!(msg, Msg::WatchError { .. }),
                    "unexpected watch error"
                );
                let done =
                    matches!(&msg, Msg::Synced { generation } if *generation == app.generation);
                app.handle_msg(msg);
                if done {
                    return;
                }
            }
        })
        .await
        .expect("owner view never synced");

        assert_eq!(app.kind_plural, owner_plural);
        assert_eq!(row_names(&app), [owner]);
        let mut owner_requests = Vec::new();
        while let Ok(uri) = requests.try_recv() {
            if uri.path().ends_with(owner_plural) {
                owner_requests.push(uri.query().unwrap_or("").to_owned());
            }
        }
        assert!(
            owner_requests[0].contains("sendInitialEvents=true"),
            "{owner_requests:#?}"
        );
        assert!(
            owner_requests
                .iter()
                .any(|query| !query.contains("watch=true")
                    && query.contains(&format!("fieldSelector=metadata.name%3D{owner}"))),
            "no plain list of the owner: {owner_requests:#?}"
        );
        app.handle_key(press(KeyCode::Char('q'))).unwrap();
    }
}

/// A streaming re-list after an expired watch can stall behind a buffering
/// proxy just like the first list, so it falls back to a plain list too.
#[tokio::test]
async fn a_stalled_streaming_relist_falls_back_to_a_plain_list() {
    use futures_util::stream;
    use hyper::body::{Bytes, Frame};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let streams = Arc::new(AtomicUsize::new(0));
    let (seen, mut requests) = mpsc::unbounded_channel();
    let streamed = Arc::clone(&streams);
    let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
        let uri = request.uri().clone();
        seen.send(uri.clone()).ok();
        let query = uri.query().unwrap_or("").to_owned();
        let watch = query.contains("watch=true");
        let streaming = query.contains("sendInitialEvents=true");
        let attempt = (watch && streaming).then(|| streamed.fetch_add(1, Ordering::SeqCst));
        async move {
            let pod = json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "api", "namespace": "prod", "uid": "pod-1", "resourceVersion": "10"}});
            let body = match (watch, attempt) {
                (true, Some(0)) => {
                    let lines = [
                        json!({"type": "ADDED", "object": pod}),
                        json!({"type": "BOOKMARK", "object": {"apiVersion": "v1", "kind": "Pod", "metadata": {"resourceVersion": "10", "annotations": {"k8s.io/initial-events-end": "true"}}}}),
                        json!({"type": "ERROR", "object": {"apiVersion": "v1", "kind": "Status", "status": "Failure", "message": "too old resource version", "reason": "Expired", "code": 410}}),
                    ];
                    lines.iter().map(|line| format!("{line}\n")).collect()
                }
                // Held in the proxy's buffer: the re-list, and the plain
                // watch after a list, never answer.
                (true, _) => std::future::pending().await,
                (false, _) => json!({"apiVersion": "v1", "kind": "PodList", "metadata": {"resourceVersion": "11"}, "items": [pod]}).to_string(),
            };
            let frames = stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from(body)))]);
            let frames = if watch {
                frames.chain(stream::pending()).boxed()
            } else {
                frames.boxed()
            };
            Ok::<_, Infallible>(http::Response::new(http_body_util::StreamBody::new(frames)))
        }
    });
    let mut cluster = Cluster::fake();
    cluster.client = kube::Client::new(service, "default");
    let (mut app, mut rx) = test_app();
    app.cluster = cluster;
    app.switch_kind_ns("pods", Some("prod"));

    // The first streaming list syncs, the watch expires, and the streaming
    // re-list stalls. Only the fallback can sync the view again.
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut synced = 0;
        while synced < 2 {
            let msg = rx.recv().await.expect("watch channel closed");
            assert!(
                !matches!(msg, Msg::WatchError { .. }),
                "unexpected watch error"
            );
            if matches!(&msg, Msg::Synced { generation } if *generation == app.generation) {
                synced += 1;
            }
            app.handle_msg(msg);
        }
    })
    .await
    .expect("the stalled re-list never fell back to a plain list");

    assert_eq!(row_names(&app), ["api"]);
    assert_eq!(streams.load(Ordering::SeqCst), 2);
    let mut lists = 0;
    while let Ok(uri) = requests.try_recv() {
        if uri.path() == "/api/v1/namespaces/prod/pods"
            && !uri.query().unwrap_or("").contains("watch=true")
        {
            lists += 1;
        }
    }
    assert_eq!(lists, 1);
    app.handle_key(press(KeyCode::Char('q'))).unwrap();
}

/// An expired status without the 410 code makes the watcher resume rather
/// than list again. A quiet resumed watch sends nothing, which is no sign of
/// a buffering proxy, so the cluster keeps its streaming lists.
#[tokio::test]
async fn an_expired_status_without_410_does_not_fall_back() {
    use futures_util::stream;
    use hyper::body::{Bytes, Frame};
    use std::convert::Infallible;

    let (seen, mut requests) = mpsc::unbounded_channel();
    let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
        let uri = request.uri().clone();
        seen.send(uri.clone()).ok();
        let query = uri.query().unwrap_or("").to_owned();
        let watch = query.contains("watch=true");
        let streaming = query.contains("sendInitialEvents=true");
        async move {
            let body = if watch && streaming {
                let lines = [
                    json!({"type": "ADDED", "object": {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "api", "namespace": "prod", "uid": "pod-1", "resourceVersion": "10"}}}),
                    json!({"type": "BOOKMARK", "object": {"apiVersion": "v1", "kind": "Pod", "metadata": {"resourceVersion": "10", "annotations": {"k8s.io/initial-events-end": "true"}}}}),
                    json!({"type": "ERROR", "object": {"apiVersion": "v1", "kind": "Status", "status": "Failure", "message": "watch expired", "reason": "Expired", "code": 500}}),
                ];
                lines.iter().map(|line| format!("{line}\n")).collect()
            } else {
                // The resumed watch stays quiet.
                String::new()
            };
            let frames = stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from(body)))]);
            Ok::<_, Infallible>(http::Response::new(http_body_util::StreamBody::new(
                frames.chain(stream::pending()).boxed(),
            )))
        }
    });
    let mut cluster = Cluster::fake();
    cluster.client = kube::Client::new(service, "default");
    let (mut app, mut rx) = test_app();
    app.cluster = cluster;
    app.switch_kind_ns("pods", Some("prod"));
    sync_selector_view(&mut app, &mut rx).await;

    // Well past the fallback deadline.
    let quiet = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(quiet);
    loop {
        tokio::select! {
            () = &mut quiet => break,
            Some(msg) = rx.recv() => app.handle_msg(msg),
        }
    }
    let mut lists = 0;
    while let Ok(uri) = requests.try_recv() {
        if !uri.query().unwrap_or("").contains("watch=true") && uri.path().ends_with("/pods") {
            lists += 1;
        }
    }
    assert_eq!(lists, 0, "a quiet resumed watch fell back to list+watch");
    assert_eq!(row_names(&app), ["api"]);
    app.handle_key(press(KeyCode::Char('q'))).unwrap();
}
