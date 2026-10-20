# Проверка0.7.5

Linux x86_64, Rust1.99.1,2026-10-20. Итоговый лог:
validation-logs-0.7.5/verify.txt; структурированный итог — validation-results.json.

| Проверка | Результат |
|---|---|
| cargo test --locked | 229 passed,0 failed,10 ignored |
| fmt / Clippy all-targets -D warnings / release | Успешно |
| HTTP config | Наследование путей по приложениям, $host, Host/fallback, внешний префикс/порт, literal pchars/percent, отказ конфликтам/невалидным путям |
| Proxy trust | IPv4/IPv6 CIDR, пустой Lua table, недоверенные заголовки, цепочки и malformed RFC7239, защита от повторного повышения secure после HTTP hop |
| Настоящий TLS proxy | Verified HTTPS→HTTP, переписывание публичного пути, WS и BOSH auth/restart/bind/ping, legacy и RFC7239; cached RID reply |
| Ограничения входа | Origin, старые пути404, insecure/spoofed/untrusted403, IPv6 когда доступен |
| Upload | Отдельный внутренний путь и публичный prefix в unit PUT/GET; integrated custom $host path IQ/PUT/GET/reuse |
| Прежние сетевые сценарии | SASL/PLUS/SSDP/retry/Bind2/resume, WSS, PEP/push/preauth, logging/resource/CSI/MAM/MUC/offline — успешно |
| Native | 7 storage/module/order +1 bidirectional TLS/SASL EXTERNAL federation — успешно |
| Нагрузка | 100 аккаунтов,500 TLS клиентов,5000 ping,5000 сообщений,10000 MAM; failures=[] |

Полный итоговый прогон выполнен после изменений кода с CARGO_INCREMENTAL=0;
предварительный Clippy выявил три замечания, исправленные перед этим прогоном.
Ранее устаревшие compiler artifacts были удалены cargo clean -p rust-xmpp.
Исходные данные production не изменялись. После проверки обновлены только
инструкция, отчёт и упаковка. Команда: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh
с native reference env согласно scripts/prosody_compat/README.md.

Прокси в сетевом тесте — отдельный настоящий TLS socket forwarder с переписыванием
пути и HTTP metadata. Nginx/production proxy и настоящий Converse UI не запускались.
Изменения рабочего YAML и proxy выполняет оператор; пример — HTTP-PROXY.md.
Новые возможности не устраняют непроверенные границы из COMPATIBILITY.md.
PEP Android и DNSSEC из предыдущего сообщения остаются отдельными нерешёнными
задачами; этот выпуск их исправленными не объявляет. Прежние проверки DNSSEC
и логи0.7.4 сохранены в историческом отчёте. Нельзя заявлять полную замену Prosody.
