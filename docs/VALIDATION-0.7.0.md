# Проверка 0.7.0

Проверено 2026-10-20, Linux x86_64, Rust 1.99.1.
Полный лог: validation-logs-0.7.0/verify.txt.
Машинный отчёт: validation-results.json. Предыдущие отчёты сохранены отдельно.

| Проверка | Результат |
|---|---|
| cargo test --locked | 187 passed, 0 failed, 9 ignored |
| Clippy all-targets -D warnings; fmt; release build | Успешно |
| Logger unit | 8 тестов: levels/maps/ranges/sets, append0600, JSON/plain, redaction/escaping, threads, rotate и failed-reopen atomicity |
| Logging network | 8 сценариев с настоящим TLS и JSON-файлом: корреляция, успешный вход, wrong password/proof/binding, client disconnect, unknown/corrupt account, SIGHUP reopen и повторный вход |
| Секреты в журнале | В тестовых записях нет отправленных паролей, SASL payload/proof и body сообщения |
| SASL normalization/retry | 20 TLS1.2/1.3 × SASL1/2 случаев canonical PLAIN/authz/bind, invalid authz, aborted retry и active restart |
| Предыдущие сетевые сценарии | SCRAM/PLUS/SSDP/Android, WSS, TCP/SM/offline, SIGTERM, Bind2/inline resume, discovery/preauth, resource policies, HTTPS BOSH/WSS/upload — успешно |
| Native Prosody | 6 module/storage checks + 1 двусторонний STARTTLS/SASL EXTERNAL federation — успешно |
| Нагрузка | 100 аккаунтов, 500 TLS-соединений, 5000 ping, 5000 сообщений, 10000 MAM записей, failures=[] |

Запуск: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh. Native инструкции:
scripts/prosody_compat/README.md; нужны PROSODY_REFERENCE_SOURCE и
PROSODY_REFERENCE_LUA. Большой архив проверен в0.5.0; AF_UNIX admin требует
разрешений целевого хоста, ранее среда запрещала bind.

Тесты используют временные fixtures. На устройствах Conversations/monocles
оставшийся отказ не воспроизведён; для следующей диагностики нужен server log
одной попытки по docs/LOGGING.md. Реальные APNs/FCM, production data, Docker/UID/TLS
целевого хоста и длительная эксплуатация не проверены. Полная замена Prosody
не подтверждена; остаточные различия — docs/COMPATIBILITY.md.
