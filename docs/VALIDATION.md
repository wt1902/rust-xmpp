# Проверка 0.8.3

2026-10-21, Linux x86_64, Rust 1.99.1. Итоговый единый прогон после заморозки
исходников: [verify.txt](validation-logs-0.8.3/verify.txt).
[Machine-readable results](validation-results-0.8.3.json).

|Проверка|Результат|
|---|---|
|Rust ordinary tests|334 passed, 0 failed, 11 ignored|
|fmt / Clippy all-targets -D warnings / release|Успешно|
|Новые Rust regressions|13 archive redo + 2 rewrite crash boundaries + 14 SM journal, успешно|
|Native reference|8 module/storage + 1 TLS/SASL EXTERNAL federation, успешно|
|Archive >128 MiB|Отдельно выполненный ignored streaming test, успешно|
|Copy/restore и rewrite|Новый inode, потеря suffix, baseline0/nonzero, crash до/после rename — успешно|
|Все network regressions verify-local.sh|Успешно, включая Android, WSS/BOSH, PEP, push, MUC crash/SM resume, upload/migration|
|Slow durable IO|0/100 мс: 3 samples/scenario; 200 мс: 1 sample/scenario; exact MAM/carbons/queues и phase logs проверены|
|SIGKILL сразу после sender SM ACK|100 мс/sync, 3 сообщения, оба MAM архива, 4 resume, 9 replay, до reauth; успешно|
|Recovery sync EIO|WAL/redo: отказ handoff без удаления journal; WAL startup до listeners; retry и данные проверены|
|Offline storage-checkpoint|4 SM exports, 2 archives, durable journal removal, повтор идемпотентен|
|Общая нагрузка|500 TLS, 100 accounts, 5000 ping, 5000 messages, 10000 MAM, failures=[]|
|MUC+SM нагрузка|500 resources, 10 rooms, 25000 presence, 1500 deliveries, SIGKILL и 10 resume; успешно|

## Личная доставка

Медианы для 3 samples, при 200 мс — одна проба; числа в миллисекундах.

|Sync delay / сценарий|Body 0.8.2 → 0.8.3|Sender SM ACK 0.8.2 → 0.8.3|Проб|
|---|---:|---:|---:|
|0 мс / 1:1|25.11 → 7.87|33.41 → 15.08|3|
|0 мс / PEP → 1:1|29.71 → 20.94|32.25 → 21.86|3|
|100 мс / 1:1|1232.47 → 419.68|1641.60 → 644.08|3|
|100 мс / PEP → 1:1|2683.29 → 1378.23|3195.21 → 1581.98|3|
|200 мс / 1:1|2836.64 → 2042.56|3643.30 → 2441.99|1|
|200 мс / PEP → 1:1|5782.02 → 2676.28|6595.92 → 3094.95|1|

0 мс — отдельная последовательная quiet pair, без full verify. Финальные
100/200 мс выполнялись при фоновой работе verify; это не изолированный CPU benchmark.
Первый append включает создание/migration MAM journal. В обычном warm сообщении
6 sync вместо 16; первый — 12. Окна счётчиков могут включать heartbeat, а PEP
сценарий включает предшествующую publication. Реальные fsync/fdatasync сохранены;
interposer замедляет только isolated data_path, не меняет host mount/DNS.
Raw samples, hashes, sync counts и phase fields — validation-logs-0.8.3/*.json.

В production log 0.8.2 серверный handler занимал 4792–5549 мс; старых полей
недостаточно, чтобы доказать конкретный IO stage. Новый таймер разделяет MAM,
доставку, carbons и handled, без payload. Эти loopback результаты не доказывают
время отображения реальным Conversations/Monocles на wthome.ru.

## Нагрузка и сопоставимость

Сопоставимый повтор 0.8.2 в текущей среде: total 151.334 с,
join 104.226 с. Финальный 0.8.3: total 128.380 с,
join 94.493 с, restart 7.557 с,
peak RSS 40.87 MiB. По одной пробе; фоновые условия
различаются, вывод о CPU efficiency не делается. Исторические 45.54 с из другой
среды не являются baseline этого сравнения. Все счётчики доставки и replay
проверены, а не только открытие порта.

## Durability и native handoff

SM WAL и archive redo авторитетны после аварии. Recovery durably adopts полный
валидный journal перед публикацией; EIO regression выявляла отсутствие barrier
в предварительном кандидате a5f5b3a…, теперь проходит на final binary. Отчёты
preliminary-recovery-sync-* сохранены именно как предварительные, не результаты
0.8.2 или final. Изначальный native MUC fixture делал in-place append без передачи
владения: теперь он явно вызывает checkpoint_all перед оригинальным Prosody.
Неjournaled suffix при активном redo намеренно не объявляется external commit.
Copy/restore с новым inode сохраняет авторитет redo; внутренний rewrite
фиксирует старый native и удаление redo перед atomic replacement. Проверены
оба crash boundaries, потеря suffix после копирования и обе baseline длины.
Перед native writer/откатом требуется остановка и `storage-checkpoint CONFIG`.
[Формат, ограничения и эксплуатация](DURABLE-MESSAGE-IO.md).

Release SHA-256: `8ceb8de3a2d02bc4399b8ae817dff7e3c3fe9bff83dc0c6669b7f19210a3847a`.
Один final verify с XMPP_LOAD_CHECK=1 и native env; отдельно archive ignored test
и подробные latency/crash/EIO fixtures. Исторические результаты сохранены.
Оставшийся AF_UNIX ignored test не запускался; 10 GiB upload и реальный MinIO/AWS,
Docker build/run, GitHub/Gitea publish и настоящие APNs/FCM не повторялись.
Общие границы полной совместимости: [COMPATIBILITY.md](COMPATIBILITY.md).
