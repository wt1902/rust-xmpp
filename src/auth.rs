use crate::{lua::bounded_vm, storage::encode_name};
use anyhow::{Context, Result, ensure};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

/// Prepare a SASL authentication identity before looking up its XMPP account.
pub fn prepared_auth_username(name: &str) -> Result<String> {
    let sasl =
        stringprep::saslprep(name).map_err(|_| anyhow::anyhow!("invalid authentication name"))?;
    let prepared =
        stringprep::nodeprep(&sasl).map_err(|_| anyhow::anyhow!("invalid authentication name"))?;
    ensure!(
        !prepared.is_empty() && prepared.len() <= 1023,
        "invalid authentication name"
    );
    Ok(prepared.into_owned())
}

pub fn user_name(name: &str) -> Result<()> {
    let prepared =
        stringprep::nodeprep(name).map_err(|_| anyhow::anyhow!("invalid account name"))?;
    ensure!(
        !name.is_empty() && name.len() <= 1023 && prepared == name,
        "account name must be a normalized XMPP localpart"
    );
    Ok(())
}
fn account_path(root: &Path, domain: &str, user: &str) -> PathBuf {
    root.join(encode_name(domain))
        .join("accounts")
        .join(format!("{}.dat", encode_name(user)))
}
fn keys(password: &str, salt: &[u8], iterations: u32, hash: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let password =
        stringprep::saslprep(password).map_err(|_| anyhow::anyhow!("invalid password encoding"))?;
    macro_rules! derive {
        ($sha:ty,$n:expr) => {{
            let mut salted = [0u8; $n];
            pbkdf2::pbkdf2_hmac::<$sha>(password.as_bytes(), salt, iterations, &mut salted);
            let mut client = Hmac::<$sha>::new_from_slice(&salted)?;
            client.update(b"Client Key");
            let stored = <$sha>::digest(client.finalize().into_bytes()).to_vec();
            let mut server = Hmac::<$sha>::new_from_slice(&salted)?;
            server.update(b"Server Key");
            (stored, server.finalize().into_bytes().to_vec())
        }};
    }
    Ok(match hash {
        "SHA-1" => derive!(Sha1, 20),
        "SHA-256" => derive!(Sha256, 32),
        _ => anyhow::bail!("unsupported password_hash"),
    })
}
/// Prosody `internal_hashed` stores binary salt and hex-encoded SCRAM keys.
#[derive(Clone, Debug)]
pub struct ScramCredentials {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
}
pub fn load_scram(
    root: &Path,
    domain: &str,
    user: &str,
    hash: &str,
) -> Result<Option<ScramCredentials>> {
    if user_name(user).is_err() {
        return Ok(None);
    }
    let file = match fs::File::open(account_path(root, domain, user)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut data = Vec::new();
    file.take(65537).read_to_end(&mut data)?;
    ensure!(data.len() <= 65536, "account record too large");
    ensure!(
        !data.starts_with(b"\x1bLua"),
        "binary Lua account record rejected"
    );
    let lua = bounded_vm().map_err(|e| anyhow::anyhow!("{e}"))?;
    let env = lua.create_table().map_err(|e| anyhow::anyhow!("{e}"))?;
    let table: mlua::Table = lua
        .load(data)
        .set_environment(env)
        .eval()
        .map_err(|_| anyhow::anyhow!("invalid account record"))?;
    let read = || -> mlua::Result<Option<ScramCredentials>> {
        if table.get::<Option<bool>>("disabled")?.unwrap_or(false) {
            return Ok(None);
        }
        // Legacy plaintext accounts are derivable without changing the original record.
        if let Some(password) = table.get::<Option<String>>("password")? {
            let salt = uuid::Uuid::new_v4().to_string().into_bytes();
            let iterations = 10000;
            let (stored_key, server_key) =
                keys(&password, &salt, iterations, hash).map_err(mlua::Error::external)?;
            return Ok(Some(ScramCredentials {
                salt,
                iterations,
                stored_key,
                server_key,
            }));
        }
        let salt: mlua::LuaString = table.get("salt")?;
        let iterations: u32 = table.get("iteration_count")?;
        let stored: String = table.get("stored_key")?;
        let server: String = table.get("server_key")?;
        Ok(Some(ScramCredentials {
            salt: salt.as_bytes().to_vec(),
            iterations,
            stored_key: hex::decode(stored).map_err(mlua::Error::external)?,
            server_key: hex::decode(server).map_err(mlua::Error::external)?,
        }))
    };
    let result = read().map_err(|_| anyhow::anyhow!("unsupported/incomplete account record"))?;
    if let Some(ref c) = result {
        let len = match hash {
            "SHA-1" => 20,
            "SHA-256" => 32,
            _ => anyhow::bail!("unsupported password_hash"),
        };
        ensure!(
            c.stored_key.len() == len
                && c.server_key.len() == len
                && !c.salt.is_empty()
                && (1..=1_000_000).contains(&c.iterations),
            "invalid SCRAM credentials"
        );
    }
    Ok(result)
}
pub fn verify(root: &Path, domain: &str, user: &str, password: &str, hash: &str) -> Result<bool> {
    ensure!(password.len() <= 4096, "password too large");
    let Ok(user) = prepared_auth_username(user) else {
        return Ok(false);
    };
    let Some(c) = load_scram(root, domain, &user, hash)? else {
        return Ok(false);
    };
    let (stored, server) = keys(password, &c.salt, c.iterations, hash)?;
    Ok(bool::from(
        stored.ct_eq(&c.stored_key) & server.ct_eq(&c.server_key),
    ))
}
/// Changes a password while preserving all unrelated Prosody account fields.
pub fn set_password(
    root: &Path,
    domain: &str,
    user: &str,
    password: &str,
    hash: &str,
) -> Result<()> {
    use crate::storage::{self, LuaValue};
    user_name(user)?;
    ensure!(
        !password.is_empty() && password.len() <= 4096,
        "invalid password length"
    );
    // `update` serializes mutations; verify existence inside its closure to avoid creating accounts.
    storage::update(root, domain, Some(user), "accounts", |account| {
        ensure!(
            account_path(root, domain, user).is_file(),
            "account does not exist"
        );
        let iterations = account
            .get("iteration_count")
            .and_then(LuaValue::as_i64)
            .unwrap_or(10000)
            .max(10000);
        ensure!(iterations <= 1_000_000, "invalid iteration count");
        let salt = uuid::Uuid::new_v4().to_string();
        let (stored, server) = keys(password, salt.as_bytes(), iterations as u32, hash)?;
        account.set("stored_key", hex::encode(stored).into());
        account.set("server_key", hex::encode(server).into());
        account.set("salt", salt.into());
        account.set("iteration_count", LuaValue::Integer(iterations));
        account.set("password", LuaValue::Nil);
        account.set(
            "updated",
            LuaValue::Integer(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs() as i64,
            ),
        );
        Ok(())
    })?;
    Ok(())
}
pub fn create(root: &Path, domain: &str, user: &str, password: &str, hash: &str) -> Result<()> {
    user_name(user)?;
    ensure!(
        !password.is_empty() && password.len() <= 4096,
        "invalid password length"
    );
    let salt = uuid::Uuid::new_v4().to_string();
    let it = 10000;
    let (stored, server) = keys(password, salt.as_bytes(), it, hash)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let content = format!(
        "return {{\n stored_key = \"{}\";\n server_key = \"{}\";\n salt = \"{}\";\n iteration_count = {};\n created = {};\n updated = {};\n}}\n",
        hex::encode(stored),
        hex::encode(server),
        salt,
        it,
        now,
        now
    );
    crate::storage::with_exclusive_access(|| {
        let path = account_path(root, domain, user);
        let parent = path.parent().context("no parent")?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        // Publish a fully fsynced file without replacing an existing account.
        let temp = parent.join(format!(".new-{}", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut f = options.open(&temp)?;
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
            fs::hard_link(&temp, &path).context("account already exists or cannot be published")?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        let _ = fs::remove_file(temp);
        result
    })
}
