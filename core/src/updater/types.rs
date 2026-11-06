use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpdateStatus {
    UpToDate,
    AutoAvailable,
    ManualRequired,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceUpdate {
    pub name: String,
    pub status: UpdateStatus,
    pub current_version: String,
    pub target_version: Option<String>,
    pub manual_instructions: Option<String>,   // the "How to Update" text
}
