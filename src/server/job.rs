use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use tempfile::TempPath;
use tokio::sync::{Mutex, OnceCell, broadcast};

use crate::api::Event;

pub type JobId = String;

#[derive(Debug)]
pub enum ServerJobState {
    Building,
    Done,
    Failed { error: String, error_type: String },
}

pub struct ServerJob {
    pub id: JobId,
    pub nonce: String,
    pub state: Mutex<ServerJobState>,
    pub events: broadcast::Sender<Event>,
    pub event_log: Mutex<Vec<Event>>,
    pub result: OnceCell<TempPath>,
}

impl ServerJob {
    fn new(id: JobId, nonce: String) -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        Arc::new(Self {
            id,
            nonce,
            state: Mutex::new(ServerJobState::Building),
            events: tx,
            event_log: Mutex::new(Vec::new()),
            result: OnceCell::new(),
        })
    }
}

impl ServerJob {
    pub async fn push_event(&self, event: Event) {
        self.event_log.lock().await.push(event.clone());
        let _ = self.events.send(event);
    }

    pub async fn mark_done(&self) {
        *self.state.lock().await = ServerJobState::Done;
    }

    pub async fn mark_failed(&self, error: String, error_type: String) {
        *self.state.lock().await = ServerJobState::Failed { error, error_type };
    }

    pub async fn snapshot_events(&self) -> Vec<Event> {
        self.event_log.lock().await.clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub async fn is_terminal(&self) -> bool {
        matches!(
            *self.state.lock().await,
            ServerJobState::Done | ServerJobState::Failed { .. }
        )
    }
}

pub struct JobRegistry {
    gate: AtomicBool,
    inner: DashMap<JobId, Arc<ServerJob>>,
}

#[derive(Debug)]
pub enum RegistryError {
    AlreadyAccepted,
}

impl JobRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            gate: AtomicBool::new(false),
            inner: DashMap::new(),
        })
    }

    pub fn try_register(&self) -> Result<JobId, RegistryError> {
        self.try_register_with_nonce(String::new())
    }

    pub fn try_register_with_nonce(&self, nonce: String) -> Result<JobId, RegistryError> {
        if self.gate.swap(true, Ordering::SeqCst) {
            return Err(RegistryError::AlreadyAccepted);
        }
        let id = uuid::Uuid::new_v4().to_string();
        let job = ServerJob::new(id.clone(), nonce);
        self.inner.insert(id.clone(), job);
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Option<Arc<ServerJob>> {
        self.inner.get(id).map(|r| r.clone())
    }
}
