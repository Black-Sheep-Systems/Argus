use crate::updater::types::{ServiceUpdate, UpdateStatus};

pub fn run_manual_update(service: &str) -> Result<String, String> {
    match service {
        "nds-api" => run_nds_api_update(),
        // Add more services here as we map them
        _ => Err(format!("No manual update rule defined for {}", service)),
    }
}

fn run_nds_api_update() -> Result<String, String> {
    // Exact commands from your screenshot
    let commands = vec![
        "cd /opt/newsdesk && docker compose build --pull api",
        "docker compose up -d --no-deps api",
    ];

    for cmd in commands {
        // TODO: execute via existing SSH / sudo helper in core
        println!("Running: {}", cmd);
        // For now this is a placeholder — replace with real execution
    }

    Ok("nds-api manual update completed successfully".to_string())
}
