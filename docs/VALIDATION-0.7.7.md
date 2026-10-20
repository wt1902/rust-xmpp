# Проверка0.7.7

Linux x86_64, Rust1.99.1,2026-10-20. Итоговый лог:
validation-logs-0.7.7/verify.txt; структурированный итог — validation-results.json.

| Проверка | Результат |
|---|---|
| cargo test --locked | 262 passed,0 failed,11 ignored |
| fmt / Clippy all-targets -D warnings / release | Успешно |
| Новый module unit | Link порядок/schemes, загруженные/disabled модули, flags, наследование custom paths/public prefix, неправильные типы и path collisions |
| http_altconnect wire | 10 изолированных конфигураций: настоящий HTTP и CA-verified HTTPS, XRD/JRD parity, MIME, CORS, HEAD/OPTIONS/405, query/JSONP, Host, custom mount/public prefix, HTTPS preference, HTTP fallback |
| Транспортная регрессия | WSS framing работает до и после отключения discovery; старые WS/BOSH/proxy paths/upload сценарии прошли |
| Остальные регрессии | SASL/PLUS/SSDP/Bind2/resume, PEP/push/preauth, logging/resource/CSI/MAM/MUC/offline, MUC restart — успешно |
| Native total | 8 module/storage tests +1 TLS/SASL EXTERNAL federation — успешно |
| Нагрузка | 100 аккаунтов,500 TLS клиентов,5000 ping,5000 сообщений,10000 MAM; failures=[] |

Итоговый прогон выполнен после исправления проверки Host с портом вне диапазона,
которую обнаружил новый сетевой тест. Все тесты запускают отдельные loopback
listeners и временные данные. После прогона менялись только отчёты и упаковка.
Native reference suite прежних модулей пройдена; непосредственно http_altconnect
проверен Rust unit/network и сопоставлением с supplied Lua source, без отдельного
native differential oracle этого модуля.

Команда: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh с native reference env
согласно scripts/prosody_compat/README.md. Точный скрипт включает новый wire test.

Рабочие конфиги/DNS/proxy/certificates production не изменялись; оператор должен
добавить http_altconnect и опубликовать HTTPS well-known. Инструкция:
HTTP-ALTCONNECT.md. Native HTTP/WS fallback сохранён; для строгого XEP0156 нужны
HTTPS/WSS URLs. Настоящие Converse/Monal/Conversations UI и полный production
rollout не проверены. Общие ограничения сервера — COMPATIBILITY.md.
