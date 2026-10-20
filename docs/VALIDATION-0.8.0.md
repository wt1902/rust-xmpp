# Проверка 0.8.0

Linux x86_64, Rust1.99.1, 2026-10-20. Итоговый полный прогон:
[verify.txt](validation-logs-0.8.0/verify.txt).
Структурированный отчёт: [validation-results.json](validation-results.json).

| Проверка | Результат |
|---|---|
| Rust tests | 293 passed, 0 failed, 11 ignored |
| fmt / Clippy all-targets -D warnings / release | Успешно |
| MUC SIGKILL через настоящий STARTTLS | temporary/persistent комнаты, несколько ресурсов, show/status/roles, порядок истории, подтверждённые leave/kick/demotion/password/config, фиксированный/custom grace — успешно |
| SM между процессами | SIGKILL/SIGTERM, legacy SASL/SASL2, counters, ack/replay, неверные owner/token/h, resource conflict — успешно |
| MUC offline fanout | До аутентификации Bob новое сообщение Alice уже в приватной durable SM-очереди; после resume доставка без history delay — успешно |
| Отзыв SM | Удаление аккаунта подтверждается; после повторного создания старый SM-токен отклоняется |
| MUC+SM нагрузка | 100 аккаунтов, 500 TLS-ресурсов, 10 комнат, 25000 join presence; SIGKILL и resume представителей всех комнат — успешно |
| Native reference | 8 module/storage + 1 TLS/SASL EXTERNAL federation — успешно |
| Остальные сетевые регрессии | Android SASL, WSS/BOSH/proxy/altconnect, PEP/push/preauth, resource policies, upload/S3/migration — успешно |

Нагрузка MUC+SM: connect 5.193 с; join 46.703 с;
полный сценарий 78.857 с; выборочный peak RSS 41.26 MiB.
Детали fanout, CPU, slots и replay: [muc-sm-load.json](validation-logs-0.8.0/muc-sm-load.json).
Это loopback smoke measurement, а не гарантия production capacity.

SHA-256 итоговой release-сборки: `74882319fcb467dd1e1813ab61e85441ffd3dae2f9f7961b28fd98ec5da7c89a`.
Основной прогон: `XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh`; native env описан
в scripts/prosody_compat/README.md. В этой среде дополнительно применены
CARGO_INCREMENTAL=0, CARGO_PROFILE_DEV_DEBUG=0, CARGO_PROFILE_TEST_DEBUG=0.

Первый основной прогон остановился на пятисекундном readiness timeout нового
нагрузочного теста после успешных обычных и сетевых проверок. В самом тесте
таймаут увеличен до60секунд; нагрузка500 повторена с той же release-сборкой,
а native-проверки выполнены отдельно. verify.txt объединяет успешные части
этих запусков; первоначальный лог сохранён в initial-load-timeout.txt.

В процессе проверки исправлены потеря сохранённых presence/history, защита
истёкших recovery claims, отсутствие успешного ответа при удалении аккаунта,
учёт stanza до SM enable и потеря MUC fanout до подключения другого участника.
Первоначальный тест последнего случая принимал позднюю историю за доставку;
итоговый тест проверяет именно private pending queue до аутентификации.

Реальные TCP/TLS-сокеты после завершения процесса отсутствуют: требуется новое
защищённое аутентифицированное соединение. SM допускает повторную доставку при
неопределённом сетевом результате; это не exactly-once транзакция между всеми
хранилищами и сетью. Известные встроенные возможности MUC перенесены, произвольные
community Lua-модули не исполняются. Пределы записей и порядок восстановления:
[MUC-RECOVERY.md](MUC-RECOVERY.md). Полная замена всей установки и проверка
реальными клиентами этим не заявляются: [COMPATIBILITY.md](COMPATIBILITY.md).

10GiB upload в0.8.0 не повторялся. Исторические испытания local/MinIO находятся
в VALIDATION-0.7.8.md и VALIDATION-0.7.9.md; их результаты не приписываются новой сборке.
