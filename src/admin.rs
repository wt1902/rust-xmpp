//! Prosody adminstream wire protocol with a deliberately explicit command surface.
//! Unsupported Lua expressions and commands return errors instead of pretending success.
use crate::{
    auth,
    wire::{Framer, escape},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    time::timeout,
};
const NS: &str = "xmpp:prosody.im/admin";
const STREAM: &str = "http://etherx.jabber.org/streams";
const HEADER: &str =
    "<stream:stream xmlns='xmpp:prosody.im/admin' xmlns:stream='http://etherx.jabber.org/streams'>";
#[derive(Clone, Debug, Default)]
pub struct AdminSnapshot {
    pub uptime: Duration,
    pub sessions: Vec<String>,
}
#[derive(Clone, Debug, Default)]
pub struct AdminReply {
    pub output: Vec<String>,
    pub message: String,
    pub error: bool,
}
pub type UserMutation = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;
#[derive(Clone)]
pub struct AdminBackend {
    pub data: PathBuf,
    /// Authentication domains and their password_hash setting.
    pub hosts: BTreeMap<String, String>,
    pub modules: BTreeMap<String, Vec<String>>,
    pub snapshot: Arc<dyn Fn() -> AdminSnapshot + Send + Sync>,
    pub delete_user: Option<UserMutation>,
    /// Invoked after disabling an account, to disconnect its sessions.
    pub disconnect_user: Option<UserMutation>,
}
#[derive(Clone, Debug)]
struct Command {
    section: String,
    name: String,
    args: Vec<Option<String>>,
}
fn strings(expression: &str) -> Result<Vec<Option<String>>> {
    let lua = crate::lua::bounded_vm().map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let env = lua
        .create_table()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let table: mlua::Table = lua
        .load(format!("return {expression}"))
        .set_environment(env)
        .eval()
        .map_err(|_| anyhow::anyhow!("expected string arguments"))?;
    let mut max_index = 0usize;
    for pair in table.clone().pairs::<mlua::Value, mlua::Value>() {
        let (key, value) = pair.map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let mlua::Value::Integer(index) = key else {
            bail!("arguments must be an array")
        };
        ensure!((1..=16).contains(&index), "too many arguments");
        ensure!(
            matches!(value, mlua::Value::String(_) | mlua::Value::Nil),
            "only string arguments are supported"
        );
        max_index = max_index.max(index as usize);
    }
    let mut result = vec![];
    for index in 1..=max_index {
        let value: mlua::Value = table
            .raw_get(index)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        result.push(match value {
            mlua::Value::String(s) => Some(
                s.to_str()
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?
                    .to_string(),
            ),
            mlua::Value::Nil => None,
            _ => bail!("only string arguments are supported"),
        });
    }
    Ok(result)
}
fn parse(line: &str) -> Result<Command> {
    ensure!(line.len() <= 16384, "command too long");
    let line = line.trim().trim_end_matches(';').trim();
    if line == "help" {
        return Ok(Command {
            section: "help".into(),
            name: "help".into(),
            args: vec![],
        });
    }
    if line.starts_with('{') {
        let mut args = strings(line)?;
        ensure!(args.len() >= 2, "expected command section and name");
        let section = args.remove(0).context("missing section")?;
        let name = args.remove(0).context("missing command")?;
        return Ok(Command {
            section,
            name,
            args,
        });
    }
    let (section, tail) = line
        .split_once(':')
        .context("expected section:command(arguments)")?;
    let (name, tail) = tail.split_once('(').context("missing command arguments")?;
    let args = tail
        .strip_suffix(')')
        .context("missing closing parenthesis")?;
    ensure!(
        [section, name]
            .iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')),
        "invalid command name"
    );
    Ok(Command {
        section: section.into(),
        name: name.into(),
        args: strings(&format!("{{{args}}}"))?,
    })
}
impl AdminBackend {
    fn account<'a>(&self, jid: &'a str) -> Result<(&'a str, &'a str, &str)> {
        ensure!(!jid.contains('/'), "expected bare JID");
        let (user, host) = jid.split_once('@').context("expected user@host")?;
        auth::user_name(user)?;
        let hash = self
            .hosts
            .get(host)
            .context("No such authentication host")?;
        Ok((user, host, hash))
    }
    fn execute(&self, c: &Command) -> Result<AdminReply> {
        let arg = |i: usize| c.args.get(i).and_then(|v| v.as_deref());
        let mut out = AdminReply::default();
        match (c.section.as_str(), c.name.as_str()) {
            ("help", _) => {
                out.output=vec!["server:version(), server:uptime(), server:status()".into(),"c2s:count(), c2s:show([jid]), host:list(), module:list([host])".into(),"user:create(jid[,password]), user:password(jid[,password]), user:delete(jid), user:disable(jid), user:enable(jid)".into()];
                out.message="Only listed commands are implemented; arbitrary Lua and module hot reload are unsupported".into();
            }
            ("server", "version") => {
                ensure!(c.args.is_empty(), "unexpected arguments");
                out.message = format!("rust-xmpp {}", env!("CARGO_PKG_VERSION"));
            }
            ("server", "status") => {
                ensure!(c.args.is_empty(), "unexpected arguments");
                out.message = "running".into();
            }
            ("server", "uptime") => {
                ensure!(c.args.is_empty(), "unexpected arguments");
                out.message = format!(
                    "This server has been running for {} seconds",
                    (self.snapshot)().uptime.as_secs()
                );
            }
            ("c2s", "count") => {
                ensure!(c.args.is_empty(), "unexpected arguments");
                out.message = format!("Total: {} clients", (self.snapshot)().sessions.len());
            }
            ("c2s", "show") => {
                ensure!(
                    c.args.len() <= 1,
                    "custom column specification is unsupported"
                );
                out.output = (self.snapshot)()
                    .sessions
                    .into_iter()
                    .filter(|j| {
                        arg(0).is_none_or(|a| a == "*" || a == j || a == crate::protocol::bare(j))
                    })
                    .collect();
                out.output.sort();
                out.message = format!("{} c2s sessions shown", out.output.len());
            }
            ("host", "list") => {
                ensure!(c.args.is_empty(), "unexpected arguments");
                out.output = self.modules.keys().cloned().collect();
                out.message = format!("{} hosts", out.output.len());
            }
            ("module", "list") => {
                ensure!(c.args.len() <= 1, "unexpected arguments");
                if let Some(host) = arg(0) {
                    let modules = self.modules.get(host).context("No such host")?;
                    out.output = modules.clone();
                } else {
                    for (host, modules) in &self.modules {
                        out.output.push(format!("{host}: {}", modules.join(", ")));
                    }
                }
                out.message = "Modules listed".into();
            }
            ("user", "create" | "password") => {
                ensure!(
                    c.args.len() == 2,
                    "expected JID and password; custom roles are unsupported"
                );
                let jid = arg(0).context("missing JID")?;
                let password = arg(1).context("missing password")?;
                let (user, host, hash) = self.account(jid)?;
                if c.name == "create" {
                    auth::create(&self.data, host, user, password, hash)?;
                    out.message = format!("Created {jid}");
                } else {
                    auth::set_password(&self.data, host, user, password, hash)?;
                    out.message = "User password changed".into();
                }
            }
            ("user", "delete") => {
                ensure!(c.args.len() == 1, "expected JID");
                let jid = arg(0).context("missing JID")?;
                self.account(jid)?;
                let delete = self.delete_user.as_ref().context(
                    "user:delete is unsupported: no complete deletion backend is configured",
                )?;
                delete(jid)?;
                out.message = "User deleted".into();
            }
            ("user", "disable" | "enable") => {
                ensure!(c.args.len() == 1, "expected JID");
                let jid = arg(0).context("missing JID")?;
                let (user, host, _) = self.account(jid)?;
                ensure!(
                    crate::storage::load(&self.data, host, Some(user), "accounts")?.is_some(),
                    "No such user"
                );
                crate::storage::update(&self.data, host, Some(user), "accounts", |v| {
                    v.set(
                        "disabled",
                        crate::storage::LuaValue::Bool(c.name == "disable"),
                    );
                    Ok(())
                })?;
                if c.name == "disable"
                    && let Some(disconnect) = &self.disconnect_user
                {
                    disconnect(jid)
                        .context("Account disabled, but disconnecting sessions failed")?;
                }
                out.message = if c.name == "disable" {
                    "User disabled"
                } else {
                    "User enabled"
                }
                .into();
            }
            _ => bail!(
                "Unsupported command {}:{}; type help for implemented commands",
                c.section,
                c.name
            ),
        }
        Ok(out)
    }
    pub fn execute_line(&self, line: &str) -> Result<AdminReply> {
        self.execute(&parse(line)?)
    }
}
pub struct AdminServer {
    listener: UnixListener,
    path: PathBuf,
    inode: u64,
    backend: AdminBackend,
    uid: u32,
}
impl AdminServer {
    pub fn bind(path: &Path, backend: AdminBackend) -> Result<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        if let Ok(meta) = fs::symlink_metadata(path) {
            ensure!(
                meta.file_type().is_socket(),
                "admin path exists and is not a socket"
            );
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => bail!("admin socket is already in use"),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path)?
                }
                Err(e) => return Err(e.into()),
            }
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
            .context("create admin Unix socket")?;
        socket
            .bind(&socket2::SockAddr::unix(path)?)
            .context("bind admin Unix socket")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        socket.listen(32).context("listen admin Unix socket")?;
        socket.set_nonblocking(true)?;
        let listener = UnixListener::from_std(socket.into())?;
        let meta = fs::metadata(path)?;
        Ok(Self {
            listener,
            path: path.into(),
            inode: meta.ino(),
            uid: meta.uid(),
            backend,
        })
    }
    pub async fn serve(self) -> Result<()> {
        let semaphore = Arc::new(Semaphore::new(32));
        loop {
            let (stream, _) = self.listener.accept().await?;
            let creds = stream.peer_cred()?;
            if creds.uid() != self.uid && creds.uid() != 0 {
                continue;
            }
            let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                continue;
            };
            let backend = self.backend.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = connection(stream, backend).await;
            });
        }
    }
}
impl Drop for AdminServer {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.inode) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
async fn send<S: AsyncWrite + Unpin>(s: &mut S, xml: &str) -> Result<()> {
    timeout(Duration::from_secs(15), s.write_all(xml.as_bytes())).await??;
    Ok(())
}
async fn read<S: AsyncRead + Unpin>(s: &mut S, f: &mut Framer) -> Result<String> {
    let text = timeout(Duration::from_secs(300), f.next(s)).await??;
    if text.starts_with("<?xml")
        || f.is_stream_end(&text)
        || crate::wire::StreamHeader::parse(&text).is_ok()
    {
        return Ok(text);
    }
    let w = f.wrap(&text);
    let d = roxmltree::Document::parse(&w)?;
    let n = d
        .root_element()
        .first_element_child()
        .context("missing admin frame")?;
    Ok(crate::protocol::xml(n))
}
fn wrapped(xml: &str) -> String {
    format!("<root xmlns='{NS}' xmlns:stream='{STREAM}'>{xml}</root>")
}
fn header_valid(text: &str) -> Result<()> {
    let header = crate::wire::StreamHeader::parse(text)?;
    ensure!(
        header.default_namespace() == Some(NS),
        "invalid admin stream namespace"
    );
    Ok(())
}
async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    backend: AdminBackend,
) -> Result<()> {
    let mut f = Framer::default();
    let mut opening = read(&mut stream, &mut f).await?;
    if opening.starts_with("<?xml ") {
        opening = read(&mut stream, &mut f).await?;
    }
    header_valid(&opening)?;
    send(&mut stream, HEADER).await?;
    loop {
        let text = read(&mut stream, &mut f).await?;
        if f.is_stream_end(&text) {
            send(&mut stream, "</stream:stream>").await?;
            return Ok(());
        }
        let command = (|| -> Result<Command> {
            let w = wrapped(&text);
            let d = roxmltree::Document::parse(&w)?;
            let n = d
                .root_element()
                .first_element_child()
                .context("empty request")?;
            ensure!(
                n.tag_name().namespace() == Some(NS) && n.tag_name().name() == "repl-input",
                "expected repl-input"
            );
            ensure!(
                !n.children().any(|n| n.is_element()),
                "unexpected command child"
            );
            parse(n.text().unwrap_or(""))
        })();
        let result = if let Ok(mut command) = command {
            if command.section == "user"
                && matches!(command.name.as_str(), "create" | "password")
                && command.args.len() == 1
            {
                let id = uuid::Uuid::new_v4().simple().to_string();
                send(
                    &mut stream,
                    &format!("<repl-request-input type='password' id='{id}'/>"),
                )
                .await?;
                let reply = read(&mut stream, &mut f).await?;
                let password = (|| -> Result<String> {
                    let w = wrapped(&reply);
                    let d = roxmltree::Document::parse(&w)?;
                    let n = d
                        .root_element()
                        .first_element_child()
                        .context("missing requested input")?;
                    ensure!(
                        n.tag_name().namespace() == Some(NS)
                            && n.tag_name().name() == "repl-requested-input"
                            && n.attribute("id") == Some(id.as_str()),
                        "unexpected requested input"
                    );
                    ensure!(
                        n.attribute("status").unwrap_or("submit") == "submit",
                        "password input cancelled"
                    );
                    Ok(n.text().unwrap_or("").into())
                })();
                match password {
                    Ok(password) => {
                        command.args.push(Some(password));
                        let b = backend.clone();
                        tokio::task::spawn_blocking(move || b.execute(&command)).await?
                    }
                    Err(e) => Err(e),
                }
            } else {
                let b = backend.clone();
                tokio::task::spawn_blocking(move || b.execute(&command)).await?
            }
        } else {
            Err(command.err().unwrap())
        };
        match result {
            Ok(reply) => {
                for line in reply.output {
                    send(
                        &mut stream,
                        &format!("<repl-output>{}</repl-output>", escape(&line)),
                    )
                    .await?;
                }
                send(
                    &mut stream,
                    &format!("<repl-result>OK: {}</repl-result>", escape(&reply.message)),
                )
                .await?;
            }
            Err(e) => {
                send(
                    &mut stream,
                    &format!(
                        "<repl-result type='error'>Error: {}</repl-result>",
                        escape(&e.to_string())
                    ),
                )
                .await?
            }
        }
    }
}
/// One command over the real admin socket. Used by CLI and health checks.
pub async fn query(path: &Path, line: &str, password: Option<&str>) -> Result<AdminReply> {
    let mut s = timeout(Duration::from_secs(5), UnixStream::connect(path)).await??;
    query_stream(&mut s, line, password).await
}
async fn query_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: &mut S,
    line: &str,
    password: Option<&str>,
) -> Result<AdminReply> {
    let mut f = Framer::default();
    send(&mut s, HEADER).await?;
    header_valid(&read(&mut s, &mut f).await?)?;
    send(
        &mut s,
        &format!("<repl-input repl='0'>{}</repl-input>", escape(line)),
    )
    .await?;
    let mut reply = AdminReply::default();
    loop {
        let text = read(&mut s, &mut f).await?;
        let w = wrapped(&text);
        let d = roxmltree::Document::parse(&w)?;
        let n = d
            .root_element()
            .first_element_child()
            .context("empty admin response")?;
        ensure!(
            n.tag_name().namespace() == Some(NS),
            "invalid admin response namespace"
        );
        match n.tag_name().name() {
            "repl-output" => reply.output.push(n.text().unwrap_or("").into()),
            "repl-result" => {
                reply.message = n.text().unwrap_or("").into();
                reply.error = n.attribute("type") == Some("error");
                let _ = send(&mut s, "</stream:stream>").await;
                return Ok(reply);
            }
            "repl-request-input" => {
                let id = n.attribute("id").context("missing request ID")?;
                ensure!(
                    n.attribute("type") == Some("password"),
                    "unsupported input request"
                );
                let status = if password.is_some() {
                    "submit"
                } else {
                    "cancel"
                };
                send(
                    &mut s,
                    &format!(
                        "<repl-requested-input id='{}' status='{status}'>{}</repl-requested-input>",
                        escape(id),
                        escape(password.unwrap_or(""))
                    ),
                )
                .await?;
            }
            _ => bail!("unexpected admin response"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn backend(path: &Path) -> AdminBackend {
        AdminBackend {
            data: path.into(),
            hosts: BTreeMap::from([("example.com".into(), "SHA-256".into())]),
            modules: BTreeMap::from([(
                "example.com".into(),
                vec!["admin_shell".into(), "tls".into()],
            )]),
            snapshot: Arc::new(|| AdminSnapshot {
                uptime: Duration::from_secs(123),
                sessions: vec!["alice@example.com/r".into()],
            }),
            delete_user: None,
            disconnect_user: None,
        }
    }
    async fn run(backend: AdminBackend, line: &str, password: Option<&str>) -> AdminReply {
        let (mut client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(connection(server, backend));
        let result = query_stream(&mut client, line, password).await.unwrap();
        drop(client);
        let _ = task.await;
        result
    }
    #[tokio::test]
    async fn real_admin_xml_protocol_over_duplex() {
        let root = tempfile::tempdir().unwrap();
        let b = backend(root.path());
        assert_eq!(
            run(b.clone(), "server:status()", None).await.message,
            "OK: running"
        );
        assert_eq!(
            run(b.clone(), "{\"c2s\",\"count\"}", None).await.message,
            "OK: Total: 1 clients"
        );
        assert_eq!(
            run(b.clone(), "c2s:show()", None).await.output,
            vec!["alice@example.com/r"]
        );
        assert!(
            !run(
                b.clone(),
                "user:create('alice@example.com')",
                Some("secret<&password")
            )
            .await
            .error
        );
        assert!(
            auth::verify(
                root.path(),
                "example.com",
                "alice",
                "secret<&password",
                "SHA-256"
            )
            .unwrap()
        );
        assert!(
            !run(
                b.clone(),
                "user:password('alice@example.com','changed')",
                None
            )
            .await
            .error
        );
        assert!(auth::verify(root.path(), "example.com", "alice", "changed", "SHA-256").unwrap());
        assert!(
            !run(b.clone(), "user:disable('alice@example.com')", None)
                .await
                .error
        );
        assert!(!auth::verify(root.path(), "example.com", "alice", "changed", "SHA-256").unwrap());
        assert!(
            !run(b.clone(), "user:enable('alice@example.com')", None)
                .await
                .error
        );
        assert!(auth::verify(root.path(), "example.com", "alice", "changed", "SHA-256").unwrap());
        for line in [
            "module:reload('tls')",
            "os.execute('echo forbidden')",
            "user:delete('alice@example.com')",
            "user:create('bob@example.com',nil,'prosody:admin')",
        ] {
            assert!(run(b.clone(), line, None).await.error, "{line}");
        }
        assert!(
            run(b.clone(), "user:password('alice@example.com')", None)
                .await
                .error
        );
        assert!(auth::verify(root.path(), "example.com", "alice", "changed", "SHA-256").unwrap());
        let (mut client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(connection(server, b));
        client.write_all(b"<a:stream xmlns:a='http://etherx.jabber.org/streams' xmlns='xmpp:prosody.im/admin' xmlns:q='xmpp:prosody.im/admin'><q:repl-input>server:version()</q:repl-input>").await.unwrap();
        let mut f = Framer::default();
        f.next(&mut client).await.unwrap();
        assert!(f.next(&mut client).await.unwrap().contains("rust-xmpp"));
        drop(client);
        let _ = task.await;
    }
}
