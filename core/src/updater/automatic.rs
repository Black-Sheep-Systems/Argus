use crate::updater::types::{ServiceUpdate, UpdateStatus};
use crate::ssh::Session;   // uses the existing SSH session from core

/// Queries the server and returns services that have automatic updates available.
/// Replace the mock data with a real command when ready.
pub fn get_auto_update_services(session: &Session) -> Result<Vec<ServiceUpdate>, String> {
    // TODO: Replace this with a real command, e.g.:
    // let output = session.execute("argus list-updates --format json")?;
    // Then parse the JSON into Vec<ServiceUpdate>

    // Current placeholder data
    Ok(vec![
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
    ])
}

/// Runs all automatic updates using the provided SSH session.
pub fn run_automatic_updates(session: &Session) -> Result<String, String> {
    let services = get_auto_update_services(session)?;
    let mut updated = Vec::new();

    for service in services {
        if service.status == UpdateStatus::AutoAvailable {
            // Real execution placeholder – replace with actual docker commands
            let pull = format!("docker compose pull {}", service.name);
            let up = format!("docker compose up -d {}", service.name);

            // TODO: session.execute(&pull)?;
            // TODO: session.execute(&up)?;

            println!("Would run: {}", pull);
            println!("Would run: {}", up);

            updated.push(service.name);
        }
    }

    if updated.is_empty() {
        Ok("No automatic updates were needed.".to_string())
    } else {
        Ok(format!("Successfully updated: {}", updated.join(", ")))
    }
}
