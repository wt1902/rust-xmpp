# Проверка0.7.4

Проверено2026-10-20, Linux x86_64, Rust1.99.1 (восстановлен exact toolchain).
Итоговый лог validation-logs-0.7.4/verify.txt; JSON validation-results.json.

| Проверка | Результат |
|---|---|
| cargo test --locked | 215 passed, 0 failed, 10 ignored |
| fmt, Clippy all-targets -D warnings, release | Успешно |
| Converse Origin | Исходная политика: wthome.ru101, actual conversejs.wthome.ru403; исправленная: actual101 |
| HTTPS binding | HTTPS-only startup, отдельные127.0.0.1 и::1 при global interfaces127.0.0.1; wildcard/override/fallback unit |
| WSS | Проверка CA/hostname, обязательный xmpp, browser headers, оба пути,403/400/404/101, preauth open/features/close, закрытие WebSocket |
| HTTP privacy | Фиксированные route/status/TLS outcomes, никакого request URL/query/Origin/header/body в журнале |
| PEP unit | 6 новых tests: invalid IDs, signed32/duplicates, legacy/OMEMO2, payloadless event, direct first-item, privacy |
| PEP wire | STARTTLS replay/live: valid1invalid1, suppression empty event + непустой IQ, diagnostic redaction |
| Предыдущие сети | SASL/PLUS/SSDP/retry, Bind2/resume, PEP order+config migration, Gajim IBR/labels, preauth/push, logging/rotation, resource, CSI/MAM/MUC/offline, BOSH/WSS/upload — успешно |
| Native | 7 storage/module/order tests +1 двусторонняя STARTTLS/SASL EXTERNAL федерация — успешно |
| Нагрузка | 100 аккаунтов,500 TLS-соединений,5000 ping,5000 сообщений,10000 MAM записей; failures=[] |
| Client log filter | Синтетический ввод с приватными маркерами выдаёт только фиксированные причины, без XML/ID/token |
| DNSSEC | Повторные DS/DNSKEY: NOERROR без Answer, AD=false; production DNS не менялся |

Итоговый прогон выполнен после изменений исходников; последующие изменения
касаются отчётов/упаковки. Scripts/*.sh сохранены executable в ZIP.
Native reference заново извлечён из supplied archive и собран с настоящими
Lua5.4.6/LuaSec/LuaSocket/ICU/OpenSSL модулями в private prefix. Запуск:
XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh с PROSODY_REFERENCE_SOURCE,
PROSODY_REFERENCE_LUA и native prefix env из scripts/prosody_compat/README.md.

Серверный журнал0.7.3:12 own OMEMO IQ,0 own errors, XML device counts1/2/6.
Этот факт не доказывает валидность IDs/содержимое уведомлений и не устанавливает
причину Android pepBroken. Клиентского журнала у пользователя нет. Текущий патч
НЕ объявляет PEP проблему устранённой; добавлена необходимая безопасная диагностика.
Converse origin подтверждён пользователем; пример updated, рабочий YAML на
целевом сервере требует явного добавления Origin. Прямой read-only probe live
WSS не смог разрешить production DNS из этой среды. Браузерный UI не запускался.

No wildcard Origin/TLS bypass. Нельзя утверждать полную замену Prosody:
не проверены полная production миграция, настоящие приложения/APNs/FCM,
целевой Docker/UID/TLS и длительная эксплуатация. Большой архив последний раз
проверен0.5.0, AF_UNIX admin требует разрешённого хоста. COMPATIBILITY.md.
