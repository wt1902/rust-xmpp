# Проверка 0.7.8

Linux x86_64, Rust 1.99.1, 2026-10-20. Полный лог: validation-logs-0.7.8/verify.txt.
Структурированный отчёт: validation-results.json; large.json содержит измерения реальной передачи.

| Проверка | Результат |
|---|---|
| cargo test --locked | 262 passed, 0 failed, 11 ignored |
| fmt / Clippy all-targets -D warnings / release | Успешно |
| Несколько upload components | Hosts/paths, discovery, quota/JWT/object isolation, restart, WS/BOSH/host-meta composition, ambiguous mount rejection — успешно |
| S3 wire | Независимая проверка SigV4, multipart, ошибки/abort/retry, ambiguous completion, SIGKILL и startup recovery, range/conditional/expiry — успешно |
| Реальный HTTPS local upload | 10737418240 байт PUT и полный GET, SHA-256 совпал; реально выделены дисковые блоки |
| Большой файл | PUT 14.39 с; GET 69.22 с; Range за 4 GiB, HEAD, reuse409, quota — успешно |
| Выборочный RSS каждые 50 мс | Сервер 17.24 MiB; клиент 20.19 MiB |
| Native reference | 8 module/storage + 1 TLS/SASL EXTERNAL federation — успешно |
| Нагрузка | 100 аккаунтов, 500 TLS клиентов, 5000 ping, 5000 сообщений, 10000 MAM; failures=[] |

Команда полного прогона: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh с native
reference env согласно scripts/prosody_compat/README.md.
Большой файл отдельно: python3 tests/upload_large_network.py --binary target/release/rust-xmpp.
Его 10 GiB временные данные удалены после проверки. Ошибка PID namespace в первом
измерителе RSS исправлена; итоговый прогон выполнен повторно с ненулевыми измерениями.
RSS — выборочный максимум, а не гарантия точного пика при любой нагрузке.

S3 проверен на независимом локальном HTTP protocol fixture; AWS/MinIO и реальная
передача 10 GiB в object store не проверены. Сервер использует multipart 8 MiB,
до восьми активных uploads на component. Для остаточных multipart sessions в
окне аварии до сохранения UploadId требуется bucket lifecycle
AbortIncompleteMultipartUpload. Настройка и ограничения: HTTP-UPLOAD.md.

Полная совместимость с Prosody и работа настоящих клиентов в production этим
прогоном не заявляются. Остальные ограничения: COMPATIBILITY.md. После финального
прогона исходники сервера не изменялись; менялись только отчёты и упаковка.
