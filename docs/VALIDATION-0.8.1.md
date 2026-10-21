# Проверка 0.8.1

2026-10-21, Linux x86_64, Rust1.99.1. Итоговый **единый** прогон:
[verify.txt](validation-logs-0.8.1/verify.txt). Структурированный отчёт:
[validation-results.json](validation-results.json).

| Проверка | Результат |
|---|---|
| cargo tests |297 passed,0failed,11ignored в обычном наборе|
| fmt / Clippy all-targets -D warnings / release |Успешно|
| Новые структурные регрессии |2CSI mutation/rollback +2MUC archive scan/native export/retry — успешно|
| Сеть |Весь verify-local.sh, включая10MUC crash cases, SM restart/offline fanout, PEP/push, Android SASL, WSS/BOSH/proxy, upload/S3/migration — успешно|
| Native reference |8module/storage +1TLS/SASL EXTERNAL federation — успешно|
| Общая нагрузка |100accounts,500TLS,5000ping,5000messages,10000MAM,failures=[]|
| MUC+SM нагрузка |500resources,10rooms,25000presence,1500deliveries,SIGKILL и10resume — успешно|
| Latency regression |0/10000records в полном прогоне; отдельное сравнение0/1000/10000/100000 до/после — успешно|

MUC+SM connect 3.149с; join 25.54с;
весь сценарий 39.535с; выборочный peakRSS 41.25MiB.

100000записей, active CSI MUC peer: median 2517.940→4.680мс,
p95 2520.941→14.532мс. Inactive CSI median
3866.027→4.285мс. По3samples/state для большого архива;
это loopback измерение с проверкой точного количества MAM-записей, не production SLA.
Сырые samples: validation-logs-0.8.1/latency-*.json.
Причины и изменения: [MESSAGE-LATENCY.md](MESSAGE-LATENCY.md).

Release SHA-256: `c57757476f2019c60ac877e4a66364b17283218e3cc244ae3f29cde1d3be2977`. Baseline0.8.0 SHA-256:
`74882319fcb467dd1e1813ab61e85441ffd3dae2f9f7961b28fd98ec5da7c89a`. Отчёты автоматически связывают результат с бинарником.

Повторение: `XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh` с native env
по scripts/prosody_compat/README.md. Использованы CARGO_INCREMENTAL=0,
CARGO_PROFILE_DEV_DEBUG=0 и CARGO_PROFILE_TEST_DEBUG=0; native Lua-зависимости
из Ubuntu packages извлечены в частный /tmp prefix из-за ограничений среды.
Оригинальные compiled Prosody modules предоставленной ревизии сохранены.

Никакой fsync не отключён. Подтверждённые изменения MUC/SM остаются durable,
CSI queue mutation откатывается при ошибке записи. Старые crash/owner/token/h/
account deletion/recreation тесты проходят. Периодический maintenance и MAM
queries всё ещё работают с архивом; исправление устраняет scan на каждый append,
а не обещает постоянную стоимость любой архивной операции.

Ignored native9тестов выполнены отдельно внутри того же verify-local.sh.
Оставшиеся AF_UNIX admin и>128MiB archive tests по-прежнему входят в полный CI
entrypoint, но в этом локальном прогоне не запускались. Передачи10GiB не
повторялись: старые0.7.8/0.7.9отчёты не относятся к новой сборке.
Настоящие production клиенты, DNSSEC, APNs/FCM и полный Prosody parity этим
не подтверждаются. Общие пределы: [COMPATIBILITY.md](COMPATIBILITY.md).
