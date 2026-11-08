# Argus

Desktop admin app for the Black Sheep Server. Design: `claude/argus-design.md` in the Inventory Control System project.

Phase 1, unfinished: `core/` holds the SSH sign-in (key + passphrase, then authenticator code, server key pinned).

Check the sign-in:

    cd core
    cargo run --bin argus-signin-check

It asks for the key passphrase, then the authenticator code, runs `whoami` on the server, and disconnects.

## Server helper

`server/argus-helper` is installed on the server as `/usr/local/sbin/argus-helper` (root, 0755). Argus calls it as
`sudo -n /usr/local/sbin/argus-helper --session <id> <action>`. Each call is logged to `/var/log/argus/actions.log`.
Phase 1 has one action, `status`, which is read-only.

The Hephaestus version shown on the dashboard comes from `/var/lib/argus/heph-deployed`, which is updated at each deploy.

## Dashboard (phase 1, read-only)

Build once (or after changing `native/` or `core/`):

    cd native
    cargo build --release
    copy target\release\argus_native.dll ..\app\native\argus_native.node
    cd ..\app
    npm install

Run:

    cd app
    npm start

Limits: the passphrase and code pass through JavaScript strings, which cannot be wiped from memory; russh keeps one plain copy of the code (valid about 30 seconds). A Disconnect pressed during sign-in does not cancel the sign-in already under way (the screen does not offer that today).
