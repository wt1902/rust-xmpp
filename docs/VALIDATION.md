# Проверка 0.7.9

Linux x86_64, Rust 1.99.1, 2026-10-20. Полный итоговый прогон:
validation-logs-0.7.9/verify.txt. Структурированный отчёт: validation-results.json.

| Проверка | Результат |
|---|---|
| cargo test --locked | 265 passed, 0 failed, 11 ignored |
| fmt / Clippy all-targets -D warnings / release | Успешно |
| Upload migration | local → S3 A → S3 B → local, SHA-256, прежние URL/JWT/HEAD, native metadata/source, dry run, lock, прерывание/resume и startup barrier — успешно |
| S3 recovery | Intent до initiation, отсутствие UploadId, pagination и exact-key cleanup без удаления чужого prefix, ambiguous completion, quarantine и late commit — успешно |
| Конкурентный PUT | Регрессия: захват слота читает свежие completion/quarantine flags атомарно — успешно |
| Реальная передача через MinIO | 10,737,418,240 байт PUT и полный GET; SHA-256 совпал; объект: 1280 multipart parts |
| Время большого файла | PUT 48.453 с; GET 13.710 с |
| Выборочный RSS каждые 50 мс | Rust 101.14 MiB; клиент 23.21 MiB; MinIO 475.84 MiB |
| MinIO дополнительные проверки | Range за 4/5 GiB и хвост, restart/read/reuse409, SIGKILL после сохранённой части и abort при recovery — успешно |
| Native reference | 8 module/storage + 1 TLS/SASL EXTERNAL federation — успешно |
| Нагрузка | 100 аккаунтов, 500 TLS клиентов, 5000 ping,5000 сообщений, 10000 MAM; failures=[] |

Итоговая сборка SHA-256: 24c0dca637e7ce4e238ef6becad16bb5a18a33546554b0eecf310fd8927f021c. MinIO report автоматически записывает
тот же hash. Большая передача повторена после последних изменений сервера.
Полный прогон включает исправление гонки устаревшего snapshot при захвате слота.
Отдельные первые прогоны нашли и помогли исправить нестабильный fingerprint
миграции и пропуск немедленного reconciliation под ещё активным claim.
Финальный результат не содержит этих ошибок. RSS — выборочный максимум, а не
гарантия точного пика для любой нагрузки. Временные 10 GiB объекты после проверки удалены.

## Точная граница MinIO проверки

Использован настоящий upstream MinIO RELEASE.2025-04-22T22-12-26Z, собранный
Go1.24.3 из официального GitHub archive. Немодифицированная сборка в этой среде
не запускается: net.Interfaces/netlinkrib запрещён с EPERM. Тестовая сборка
добавляет только fallback на 127.0.0.1 для этой ошибки перечисления интерфейсов.
S3, authentication, multipart и storage code не изменены. Это не qualification
немодифицированного MinIO в обычной production среде.

Точный diff, hashes исходного архива, обеих сборок и adapter:
validation-logs-0.7.9/minio-sandbox-compat.patch и minio-provenance.json.
Полный результат и 1280-part ETag: validation-logs-0.7.9/minio.json.
Проверен single-node loopback с HTTP к MinIO и CA-verified HTTPS к gateway.
AWS account, distributed MinIO и production сеть не проверены.

## Повторение

Полный прогон: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh с native env
согласно scripts/prosody_compat/README.md. В этой среде дополнительно применены
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0.
MinIO отдельно: python3 tests/upload_minio_network.py --binary target/release/rust-xmpp
--minio /path/to/minio --report /tmp/minio-report.json. При test adapter передайте
--minio-compat-patch /path/to/patch, чтобы он попал в результат. Можно задать
MINIO_BINARY перед verify-local.sh для opt-in передачи10 GiB; нужны место и MinIO executable.

Инструкции migration/recovery: HTTP-UPLOAD.md. Source всегда сохраняется;
незавершённая миграция блокирует startup, неопределённый Complete quarantines
только свой slot. Потеря ownership metadata не позволяет безопасно удалить
произвольные чужие multiparts; bucket lifecycle остаётся дополнительной защитой.
Сетевой сбой с HEAD404 не выдаётся за доказанную неудачу удалённого commit.
Полная замена Prosody, настоящие production клиенты и DNSSEC этим не заявляются;
общие границы — COMPATIBILITY.md.
