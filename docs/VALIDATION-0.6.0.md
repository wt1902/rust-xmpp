# Проверка 0.6.0

Проверено 2026-10-20, Linux x86_64, Rust 1.99.1. Полный лог:
validation-logs-0.6.0/verify.txt. Машинный отчёт: validation-results.json.
Предыдущие отчёты сохранены отдельно.

| Проверка | Результат |
|---|---|
| cargo test --locked | 172 passed, 0 failed, 9 ignored |
| Clippy all-targets с -D warnings, fmt | Успешно |
| Release build --locked | Успешно |
| Resource conflict TLS | default/kick_old/kick_new/increment/random; live и hibernating SM; old cleanup isolation; старый token отзывается при замене |
| SM active takeover | Владелец/id/h проверяются до замены; partial replay и отдельное состояние старого транспорта |
| SASL2 inline resume | Full JID, replay после success, Bind2 suppression/fallback, неверная авторизация/owner/token/h и malformed requests |
| HTTP transport | 10 тестов BOSH/WS, включая async cleanup и graceful/abrupt disconnect |
| HTTPS BOSH + WSS | Настоящий engine, SM close и повторный вход с тем же resource под kick_new; chat, CSI, roster и upload |
| Остальные сетевые сценарии | TCP modules, offline/SM, SIGTERM, SCRAM SHA-1/SHA-256, SASL1/2/Bind2, PEP/push discovery и preauth |
| Native module oracles | 6 дополнительных ignored tests: auth/storage, PEP, MUC/MAM, CSI, push body lookup, invitation tokens |
| Native federation | Дополнительный ignored test: двусторонний STARTTLS + SASL EXTERNAL с Prosody cafd74b9c5ea |
| Нагрузка с MAM | 100 аккаунтов, 500 TLS-соединений, 5000 ping, 5000 сообщений, 10000 архивных записей; failures=[] |

Полный запуск: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh.
Для native проверок нужны переменные PROSODY_REFERENCE_SOURCE и
PROSODY_REFERENCE_LUA; инструкции в scripts/prosody_compat/README.md.
Большой архив проверен в 0.5.0 и в этом прогоне не повторялся.
AF_UNIX admin требует разрешений среды, ранее bind был запрещён.

Проверки проходят на изолированных временных данных. Настоящие Monal и
Conversations, APNs/FCM, рабочие данные, Docker/UID/TLS целевого хоста и
длительная эксплуатация не проверены. Полная замена Prosody не подтверждена;
оставшиеся функциональные различия перечислены в COMPATIBILITY.md.
