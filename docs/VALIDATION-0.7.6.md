# Проверка0.7.6

Linux x86_64, Rust1.99.1,2026-10-20. Итоговый лог:
validation-logs-0.7.6/verify.txt; структурированный итог — validation-results.json.

| Проверка | Результат |
|---|---|
| cargo test --locked | 259 passed,0 failed,11 ignored |
| fmt / Clippy all-targets -D warnings / release | Успешно |
| MUC extension tests | PM policies, hats/identity privacy, presence role transitions, язык/config/disco, offline affiliates, optional flags, MAM ACL/all/presences/totals/purge |
| История | 10 tests: count/time/char constraints, combined limits, subject/hints, ordering/delay, last-message snapshot |
| Recovery | Native state filtering/roundtrip, exact resource, expiry, persisted deadline, changed config/password deny, no stale-role replay, explicit nick change, temporary-room retention |
| Bounds | Oversized4KiB/256KiB presence status omitted;20KiB last message does not prevent membership checkpoint |
| MUC wire restart | Настоящий SIGTERM с живыми STARTTLS sockets; temporary/persistent rooms, role/show/status, чужой account/resource отказ, nick theft отказ, groupchat после восстановления |
| Native occupant state | Настоящая Prosody восстанавливает Rust state с3 sessions/2 resources; native freeze меняет роль/status, Rust читает результат |
| Прежние сети | SASL/PLUS/SSDP/Bind2/resume, PEP/push/preauth, WSS/BOSH/proxy paths/upload, logging/resource/CSI/MAM/MUC/offline — успешно |
| Native total | 8 module/storage/MUC tests +1 bidirectional TLS/SASL EXTERNAL federation — успешно |
| Нагрузка | 100 аккаунтов,500 TLS клиентов,5000 ping,5000 сообщений,10000 MAM; failures=[] |

Итоговый прогон выполнен после заморозки исходников с CARGO_INCREMENTAL=0
и очисткой package artifacts. Предварительные проверки нашли исправленные
проблемы cleanup временных комнат, повторного использования checkpoint,
необязательных oversized полей и двух Clippy замечаний. Дополнительно проверен канонический отпечаток конфигурации,
независимый от порядка ключей Lua VM. Здесь сохранён только
полный успешный прогон. После него менялись отчёты и упаковка.

Команда: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh с native reference env
согласно scripts/prosody_compat/README.md. Native source cafd74b9c5ea используется
непосредственно с Lua5.4/LuaSec/LuaSocket и compiled ICU/OpenSSL модулями.

Не проверены production migration, реальные Monal/Conversations/Gajim, SIGKILL
crash recovery и все community-модули. Контроль штатного восстановления не
означает сохранение старых TCP-сокетов или SM между процессами. Условия300s /
полный JID / неизменный config описаны в MUC-RECOVERY.md. Нативное состояние без
Rust fingerprint не даёт автоматического разрешения на восстановление.
Предыдущие PEP/DNSSEC сообщения этот выпуск не объявляет исправленными.
Полная взаимозаменяемость сервера не подтверждена: COMPATIBILITY.md.
