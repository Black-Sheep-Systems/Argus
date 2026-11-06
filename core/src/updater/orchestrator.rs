use crate::updater::{run_automatic_updates, run_manual_update, ServiceUpdate, UpdateStatus};

pub fn update_all() -> Result<String, String> {
    let mut log = String::new();

    // 1. Run automatic updates
    match run_automatic_updates() {
        Ok(msg) => log.push_str(&format!("Automatic: {}\n", msg)),
        Err(e) => return Err(format!("Automatic updates failed: {}", e)),
    }

    // 2. Get current status (placeholder – will be replaced with real query)
    let manual_services = vec!["nds-api"]; // later: query real list

    // 3. Run manual updates for services that need it
    for svc in manual_services {
        match run_manual_update(svc) {
            Ok(msg) => log.push_str(&format!("Manual {}: {}\n", svc, msg)),
            Err(e) => log.push_str(&format!("Manual {} failed: {}\n", svc, e)),
        }
    }

    // 4. Restart + refresh (placeholder)
    log.push_str("Restarting server...\n");
    // TODO: call existing restart logic
    log.push_str("Waiting 30 seconds and refreshing status...\n");
    // TODO: sleep + re-query

    Ok(log)
}
