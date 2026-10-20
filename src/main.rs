use anyhow::{Context, Result, bail};
use rust_xmpp::config;
use std::{env, path::Path};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") => {
            let path = args
                .get(1)
                .map(String::as_str)
                .unwrap_or("/etc/prosody/prosody.cfg.lua");
            let (c, d) = rust_xmpp::server::settings_config(Path::new(path))?;
            let data = c
                .option(&d, "data_path")
                .and_then(|v| v.as_str())
                .context("data_path missing")?;
            let socket = rust_xmpp::server::admin_path(&c, &d, Path::new(data));
            let reply = rust_xmpp::admin::query(&socket, "server:status()", None).await?;
            if reply.error {
                bail!("server status query failed")
            };
            println!("{}", reply.message);
        }
        Some("shell") if args.len() >= 3 => {
            let (c, d) = rust_xmpp::server::settings_config(Path::new(&args[1]))?;
            let data = c
                .option(&d, "data_path")
                .and_then(|v| v.as_str())
                .context("data_path")?;
            let path = rust_xmpp::server::admin_path(&c, &d, Path::new(data));
            let reply = rust_xmpp::admin::query(&path, &args[2], None).await?;
            for line in reply.output {
                println!("{line}");
            }
            if reply.error {
                bail!("{}", reply.message)
            }
            println!("{}", reply.message);
        }
        Some("--version") => println!(
            "rust-xmpp {} — experimental XMPP runtime",
            env!("CARGO_PKG_VERSION")
        ),
        Some("check-config") if args.len() == 2 => {
            let cfg = config::load(Path::new(&args[1]))?;
            println!(
                "Configuration parsed and basic types validated. Runtime support is checked separately by serve."
            );
            println!("Virtual hosts/components: {}", cfg.hosts.len());
            for name in cfg.hosts.keys() {
                println!(
                    "{name}: {}",
                    cfg.modules(name)?
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            for d in cfg.diagnostics() {
                println!("{} [{}]: {}", d.level, d.scope, d.message);
            }
        }
        Some("convert") if args.len() == 4 => {
            let cfg = config::load(Path::new(&args[1]))?;
            let text = match args[2].as_str() {
                "json" => serde_json::to_string_pretty(&cfg)?,
                "yaml" | "yml" => serde_yaml_ng::to_string(&cfg)?,
                "toml" => toml::to_string_pretty(&cfg)?,
                _ => bail!("output format must be json, yaml or toml"),
            };
            // Refuse overwrite; owner-only mode because converted configs contain secrets.
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts
                .open(&args[3])
                .context("cannot create output (existing files are never overwritten)")?;
            use std::io::Write;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            println!("Written {}", args[3]);
        }
        Some("serve") if args.len() == 3 && args[2] == "--experimental" => {
            rust_xmpp::server::serve(Path::new(&args[1])).await?;
        }
        Some("serve") => {
            bail!("use serve CONFIG --experimental; full Prosody replacement is not implemented")
        }
        Some("create-user") if args.len() == 4 && args[3] == "--password-stdin" => {
            let (data, domain, hash) = rust_xmpp::server::account_config(Path::new(&args[1]))?;
            let _data_guard = rust_xmpp::data_lock::DataDirectoryGuard::acquire(&data)?;
            let mut password = String::new();
            std::io::stdin().read_line(&mut password)?;
            let password = password.trim_end_matches(['\r', '\n']);
            rust_xmpp::auth::create(&data, &domain, &args[2], password, &hash)?;
            println!("Account created: {}@{}", args[2], domain);
        }
        Some("--help") | None => println!(
            "rust-xmpp check-config PATH\nrust-xmpp convert PATH json|yaml|toml OUTPUT\nrust-xmpp --version\n\nExperimental runtime: serve CONFIG --experimental\ncreate-user CONFIG USER --password-stdin\ncheck [CONFIG] (running server healthcheck)\nshell CONFIG COMMAND\n\nSTARTTLS, SCRAM/PLAIN, local messaging, roster, MAM, MUC, PEP/pubsub, stream management, push, federation and HTTP transports are implemented with limitations; see docs/COMPATIBILITY.md."
        ),
        _ => bail!("invalid command; use --help"),
    }
    Ok(())
}
