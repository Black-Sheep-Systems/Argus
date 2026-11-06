use crate::updater::types::{ServiceUpdate, UpdateStatus};

/// Returns a list of services that currently have automatic updates available.
/// In a real implementation this would query the server.
pub fn get_auto_update_services() -> Vec<ServiceUpdate> {
    // TODO: Replace this mock with a real query against the server
    vec![
        ServiceUpdate {
            name: "bss-panel".to_string(),
            status: UpdateStatus::AutoAvailable,
            current_version: "8.5".to_string(),
            target_version: Some("8.6".to_string()),
            manual_instructions: None,
        },
        ServiceUpdate {
            name: "bss-php".to_string(),
            status: UpdateStatus::AutoAvailable,
            current_version: "8.5".to_string(),
            target_version: Some("8.6".to_string()),
            manual_instructions: None,
        },
    ]
}

/// Runs all automatic updates for services that support them.
/// Returns a summary string on success.
pub fn run_automatic_updates() -> Result<String, String> {
    let services = get_auto_update_services();
    let mut updated = Vec::new();

    for service in services {
        if service.status == UpdateStatus::AutoAvailable {
            // TODO: Replace with real execution using the existing SSH client
            // Example placeholder:
            // execute_command(&format!("docker compose pull {}", service.name))?;
            // execute_command(&format!("docker compose up -d {}", service.name))?;

            updated.push(service.name);
        }
    }

    if updated.is_empty() {
        Ok("No automatic updates were needed.".to_string())
    } else {
        Ok(format!("Successfully updated: {}", updated.join(", ")))
    }
}
