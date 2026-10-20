# Проверка 0.5.0

Проверено 2026-10-20, Linux x86_64, Rust 1.99.1. Машинный отчёт:
validation-results.json. Предыдущие версии отчётов сохранены отдельно.

| Проверка | Результат |
|---|---|
| cargo test --locked | 162 passed, 0 failed, 9 ignored |
| Clippy all-targets с -D warnings | Успешно |
| cargo fmt --check | Успешно |
| Release build --locked | Успешно |
| PEP discovery | Bare-account identity и полный набор feature predicates из Monal; leaf node echo/ACL/errors |
| Push discovery | Четыре комбинации PEP × cloud_notify, правильная область identity/features, реальные enable/options/disable |
| Pre-auth TLS | Command discovery, invitation URI/expiry, RFC preapproval, взаимная подписка, single-use replay denial и account isolation |
| Unknown preauth | Forwarding и replay из pending после offline; graceful manual fallback |
| Native invitation oracle | Настоящий mod_invites читает/использует Rust token, Rust использует native token; scoped token native не принимает |
| Остальные native oracles | storage/auth SHA-1/SHA-256, PEP, MUC/MAM, CSI, push body lookup |
| Federation | Двусторонний STARTTLS + SASL EXTERNAL с настоящей Prosody cafd74b9c5ea |
| TCP, WSS, HTTPS BOSH, upload | Повторены на release 0.5.0; также SCRAM/SSDP, SASL2/Bind2, offline/SM и SIGTERM |
| Нагрузка с MAM | 100 аккаунтов, 500 TLS-соединений, 5000 ping, 5000 доставок и ровно 10 000 архивных записей |
| Большой архив | Отдельный ignored test архива больше 128 MiB |

Восемь дополнительных ignored tests выполняются отдельно: шесть native
module/storage checks, native federation и большой архив. AF_UNIX admin
socket остаётся зависимым от разрешений среды; результат попытки сохранён
в validation-logs-0.5.0. In-memory admin protocol tests входят в обычный набор.

Полный запуск: bash scripts/verify-local.sh. Новые сценарии:

```bash
python3 tests/push_discovery.py target/release/rust-xmpp
python3 tests/preauth_network.py target/release/rust-xmpp
```

Native инструкции — scripts/prosody_compat/README.md. Проверено соответствие
тестируемым клиентским predicates по исходникам, но реальные Monal/Conversations
и APNs/FCM шлюзы не запускались. Docker, UID/GID/TLS целевого хоста и копия
рабочих данных не проверены. Короткий loopback load не является длительным
benchmark полного набора модулей. Полная замена Prosody пока не подтверждена.
