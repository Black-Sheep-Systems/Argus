use crate::updater::{get_auto_update_services, run_automatic_updates, run_manual_update, ServiceUpdate, UpdateStatus};

/// Main "Update All" workflow.
/// Runs automatic updates first, then all manual ones, then restarts.
pub fn update_all() -> Result<String, String> {
    let mut log = String::new();

    // 1. Automatic updates
    match run_automatic_updates() {
        Ok(msg) => log.push_str(&format!("Automatic updates: {}\n", msg)),
        Err(e) => return Err(format!("Automatic updates failed: {}", e)),
    }

    // 2. Manual updates
    let manual_services: Vec<ServiceUpdate> = get_auto_update_services()
        .into_iter()
        .filter(|s| s.status == UpdateStatus::ManualRequired)
        .collect();

    for service in manual_services {
        match run_manual_update(&service.name) {
            Ok(msg) => log.push_str(&format!("Manual {}: {}\n", service.name, msg)),
            Err(e) => log.push_str(&format!("Manual {} failed: {}\n", service.name, e)),
        }
    }

    // 3. Restart server (placeholder)
    log.push_str("Restarting server...\n");
    // TODO: call existing restart logic from core

    // 4. Wait + refresh (placeholder)
    log.push_str("Waiting 30 seconds then refreshing status...\n");
    // TODO: std::thread::sleep + re-query status

    Ok(log)
}
