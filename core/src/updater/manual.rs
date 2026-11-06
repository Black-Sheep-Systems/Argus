use crate::ssh::Session;
use crate::updater::types::UpdateStatus;

pub fn run_manual_update(session: &Session, service: &str) -> Result<String, String> {
    match service {
        "nds-api" => run_nds_api_update(session),
        _ => Err(format!("No manual update rule defined for: {}", service)),
    }
}

fn run_nds_api_update(session: &Session) -> Result<String, String> {
    let commands = vec![
        "cd /opt/newsdesk && docker compose build --pull api",
        "docker compose up -d --no-deps api",
    ];

    for cmd in commands {
        // TODO: session.execute(cmd)?;
        println!("Executing via SSH: {}", cmd);
    }

    Ok("nds-api manual update completed".to_string())
}
