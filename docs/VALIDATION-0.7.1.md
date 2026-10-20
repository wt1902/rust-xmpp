# Проверка 0.7.1

Проверено 2026-10-20, Linux x86_64, Rust 1.99.1.
Полный лог: validation-logs-0.7.1/verify.txt. Машинный отчёт: validation-results.json.
Предыдущие отчёты сохранены отдельно.

| Проверка | Результат |
|---|---|
| cargo test --locked | 196 passed, 0 failed, 9 ignored |
| Clippy all-targets -D warnings; fmt; release build | Успешно |
| Cached SASL2 inline | 6 конфигураций: SCRAM-SHA-1/PLAIN, good/wrong password, SSDP off/on, Bind2 on/off, SM disabled cached resume, legacy bind+ping |
| Auth baseline | Поведение0.7.0 воспроизводит отказ до SCRAM challenge;0.7.1 проходит fallback |
| Gajim TLS | 4 сочетания modules on/off × allow_registration on/off; domain/ownbare disco, два каталога @to, account/password GET/SET, создание и удаление с проверкой fresh logins |
| Label catalog | 6 unit tests: оба namespace, actual example policy schema, mapping, 15 malformed/unknown schema cases; no implicit ACL |
| Logger | Объединение одинаковых destinations, независимые файлы, console aliases; прежние escaping/redaction/rotation regressions проходят |
| Предыдущие сети | TLS/PLUS/SSDP/Android, logging+SIGHUP, normalization/retry, TCP/SM/offline, Bind2/resume, discovery/preauth, resource policies, HTTPS BOSH/WSS/upload — успешно |
| Native Prosody | 6 module/storage checks + 1 двусторонний STARTTLS/SASL EXTERNAL federation — успешно |
| Нагрузка | 100 аккаунтов, 500 TLS-соединений, 5000 ping, 5000 сообщений, 10000 MAM записей; failures=[] |

Запуск: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh. Native инструкции:
scripts/prosody_compat/README.md. Нужны PROSODY_REFERENCE_SOURCE и
PROSODY_REFERENCE_LUA. Большой архив последний раз проверен в0.5.0;
AF_UNIX admin ранее был запрещён средой и требует проверки на целевом хосте.

Проверки работают с временными данными. Исходники Conversations/monocles и
Gajim проверены, но сами приложения на устройствах не запускались. Runtime
metadata catalog adapter не реализует access-control enforcement. Production
data/deployment, APNs/FCM, Docker/UID/TLS целевого хоста и длительная
эксплуатация не проверены. Полная замена Prosody пока не подтверждена;
оставшиеся различия — COMPATIBILITY.md.
