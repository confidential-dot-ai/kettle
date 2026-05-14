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
}
