use crate::ssh::Session;
use crate::updater::{get_auto_update_services, run_automatic_updates, run_manual_update, UpdateStatus};

pub fn update_all(session: &Session) -> Result<String, String> {
    let mut log = String::new();

    match run_automatic_updates(session) {
        Ok(msg) => log.push_str(&format!("Automatic: {}\n", msg)),
        Err(e) => return Err(format!("Automatic failed: {}", e)),
    }

    let manual_services = get_auto_update_services(session)?
        .into_iter()
        .filter(|s| s.status == UpdateStatus::ManualRequired)
        .collect::<Vec<_>>();

    for service in manual_services {
        match run_manual_update(session, &service.name) {
            Ok(msg) => log.push_str(&format!("Manual {}: {}\n", service.name, msg)),
            Err(e) => log.push_str(&format!("Manual {} error: {}\n", service.name, e)),
        }
    }

    log.push_str("Restarting server...\n");
    // TODO: session.execute("systemctl restart blacksheep")?;

    log.push_str("Waiting 30s and refreshing status...\n");
    // TODO: std::thread::sleep(Duration::from_secs(30));

    Ok(log)
}
