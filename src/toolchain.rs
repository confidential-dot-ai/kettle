pub(crate) mod driver;
pub(crate) use driver::*;

pub(crate) mod runner;

pub(crate) mod cargo;
pub(crate) mod cargo_lock;
pub(crate) mod nix;
pub(crate) mod pnpm;

use tokio::sync::mpsc;
use crate::api::Event;

#[derive(Clone, Default)]
pub struct EventSink(pub(crate) Option<mpsc::Sender<Event>>);

impl EventSink {
    pub fn noop() -> Self { Self(None) }
    pub fn channel(tx: mpsc::Sender<Event>) -> Self { Self(Some(tx)) }
    pub async fn emit(&self, event: Event) {
        if let Some(tx) = &self.0 {
            // Best-effort: ignore receiver-gone errors.
            let _ = tx.send(event).await;
        }
    }

    /// Synchronous, non-blocking emit. Drops the event if the channel is full or
    /// the receiver is gone. Intended for use from inside synchronous build
    /// drivers that don't have a tokio runtime handy.
    pub fn try_emit(&self, event: Event) {
        if let Some(tx) = &self.0 {
            let _ = tx.try_send(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn try_emit_returns_without_blocking_when_channel_is_full() {
        let (tx, _rx) = mpsc::channel::<Event>(1);
        let sink = EventSink::channel(tx);
        // Fill the channel.
        sink.try_emit(Event::Detect { msg: "1".into() });
        // Second try_emit must not block; on a single-thread runtime it would
        // hang the test if it did.
        sink.try_emit(Event::Detect { msg: "2".into() });
    }

    #[test]
    fn try_emit_on_noop_sink_is_a_noop() {
        let sink = EventSink::noop();
        sink.try_emit(Event::Detect { msg: "x".into() });
    }
}
