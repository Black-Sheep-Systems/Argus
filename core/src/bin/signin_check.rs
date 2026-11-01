//! Phase 1 proof: sign in as mattridge with key + passphrase + code, run
//! `whoami`, disconnect. Prints nothing secret.

use argus_core::{sign_in, Target};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME"))?;
    let key = std::path::Path::new(&home).join(".ssh").join("mattridge_vps");
    let target = Target {
        host: "129.121.98.1".into(),
        port: 22,
        user: "mattridge".into(),
        pinned_host_key: "SHA256:GnJpNrB2FnWjtqePDOeNaWHHfK1oHvESSfdz9q2EXwY".into(),
    };

    let pass = Zeroizing::new(rpassword::prompt_password("Key passphrase: ")?);
    let session = sign_in(&target, &key, pass, || {
        Ok(Zeroizing::new(rpassword::prompt_password("Authenticator code: ")?))
    })
    .await?;
    println!("Signed in. Server host key matched the pinned key.");
    let who = session.run("whoami").await?;
    anyhow::ensure!(who.trim() == target.user, "signed in as {:?}, expected {}", who.trim(), target.user);
    println!("whoami on the server: {}", who.trim());
    session.close().await?;
    println!("Disconnected.");
    Ok(())
}
