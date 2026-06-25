#![cfg(feature = "server")]

use kettle::server::event_sink::EventSink;
use kettle::api::Event;
use tokio::sync::mpsc;

#[tokio::test]
async fn channel_sink_forwards_event() {
    let (tx, mut rx) = mpsc::channel(8);
    let sink = EventSink::channel(tx);
    sink.emit(Event::Detect { msg: "cargo".into() }).await;
    let got = rx.recv().await.unwrap();
    assert!(matches!(got, Event::Detect { msg } if msg == "cargo"));
}

#[tokio::test]
async fn noop_sink_does_not_panic() {
    let sink = EventSink::noop();
    sink.emit(Event::Build { msg: "compiling".into() }).await;
}
