use crate::updater::types::{ServiceUpdate, UpdateStatus};

/// Runs the manual update procedure for a specific service.
/// Add new services here as you map them from the UI.
pub fn run_manual_update(service: &str) -> Result<String, String> {
    match service {
        "nds-api" => run_nds_api_update(),
        // Add more manual services below
        // "bss-caddy" => run_bss_caddy_update(),
        _ => Err(format!("No manual update rule defined for service: {}", service)),
    }
}

fn run_nds_api_update() -> Result<String, String> {
    // Exact commands from the UI screenshot
    let commands = vec![
        "cd /opt/newsdesk && docker compose build --pull api",
        "docker compose up -d --no-deps api",
    ];

    for cmd in commands {
        // TODO: Replace with real SSH execution using the existing core SSH client
        println!("Executing: {}", cmd);
    }

    Ok("nds-api manual update completed successfully".to_string())
}
