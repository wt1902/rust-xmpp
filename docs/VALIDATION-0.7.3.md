# Проверка 0.7.3

Проверено 2026-10-20, Linux x86_64, Rust 1.99.1.
Итоговый лог: validation-logs-0.7.3/verify.txt; validation-results.json.

| Проверка | Результат |
|---|---|
| cargo test --locked | 208 passed, 0 failed, 10 ignored |
| fmt, Clippy all-targets -D warnings, release build | Успешно |
| Baseline ZIP0.7.2 | Новый regression на исходниках предыдущего архива воспроизводит successful IQ old,current: первый список пуст, новый populated item второй |
| PEP порядок | All/recent2/recent1 читают current первым; старый item сохраняется |
| Android wire | Реальный STARTTLS, первый item как IqParser.getItem, no-to current replacement, повтор после restart; XML/ID не печатаются |
| Native порядок | Настоящий mod_pep читает те же файлы и подтверждает current,old |
| Диагностика | Unit + INFO JSON wire assertions: scope self-account, items2, first content omemo-devices, first devices2, отсутствие device IDs/raw node |
| Предыдущие проверки | SASL1/2, PLUS/SSDP, Bind2/resume, logging/rotation, Gajim discovery/register/labels, PEP/push/preauth, resource, CSI/MAM/MUC/offline, HTTP/HTTPS/BOSH/WSS/upload — успешно |
| Native Prosody | 7 module/storage/order tests +1 двусторонняя STARTTLS/SASL EXTERNAL федерация — успешно |
| Нагрузка | 100 аккаунтов, 500 TLS-соединений, 5000 ping, 5000 сообщений, 10000 MAM записей; failures=[] |
| DNSSEC | Повторный Google DS/DNSKEY read-only: NOERROR без Answer, AD=false. DNS не изменялся |

Запуск: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh; native checks требуют
PROSODY_REFERENCE_SOURCE и PROSODY_REFERENCE_LUA, инструкции
scripts/prosody_compat/README.md. Итоговый прогон выполнен после всех изменений
исходников; позже менялись только отчёты и упаковка.

В новом production журнале0.7.2: 9 auth-success, 126 PubSub IQ events,
41 OMEMO IQ и 0 OMEMO IQ errors. Это не доказывает корректное содержимое IQ.
Пользователь подтвердил полное завершение Android процессов. Мы не подменяем
диагностику рекомендацией просто переподключиться. Исправлен воспроизведённый
дефект, но реальные max_items/содержимое production узлов пока недоступны;
нельзя утверждать, что устранена единственная причина индикатора на устройстве.

Baseline log содержит намеренно упавший тест на0.7.2, а не ошибку0.7.3.
Native источник подтверждает payload-only archive, поэтому неподтверждённая
гипотеза двойного item wrapper отвергнута и не меняет данные. Синтетические
bundle bytes проверяют wire/storage, не криптографию. Native default retention1
и явные конфигурации не менялись. Реальные Android/Monal/Gajim, полная миграция,
production Docker/UID/TLS/APNs/FCM и длительная эксплуатация не проверены.
Большой архив последний раз проверен0.5.0; AF_UNIX admin требует разрешённого
хоста. Полная замена Prosody пока не подтверждена.
