# 0.7.9

- Offline CLI `upload-migrate OLD_CONFIG NEW_CONFIG --component HOST
  [--execute]`: dry run по умолчанию, local ↔ S3 и S3 ↔ S3 без удаления source.
- Последовательное копирование с проверкой размера и полным SHA-256 readback
  destination; конфликтующий объект не перезаписывается. Временный диск —
  максимум один переносимый файл дополнительно к постоянному destination.
- Durable migration journal позволяет продолжить прерванную операцию с теми
  же конфигурациями. Незавершённый или повреждённый journal блокирует startup;
  backend identity меняется только после проверки всех файлов.
- Native `uploads`/`upload_stats`, slots и JWT сохраняются; поддерживаются
  native локальные файлы без Rust completion sidecar. Миграция требует
  остановки RustXMPP и Prosody, использующих общий `data_path`.
- Multipart intent сохраняется до создания удалённого upload. Recovery
  находит потерянный UploadId через paginated listing и очищает только точный
  key принадлежащего slot. При сохранных metadata cleanup не зависит от
  lifecycle; lifecycle остаётся дополнительной защитой, а не гарантией.
- Перед completion сохраняется durable marker. Неопределённый результат
  completion при отсутствии подтверждённого объекта помещает только этот
  slot в quarantine: PUT 409, retention не удаляет его, maintenance повторяет
  сверку. Startup продолжается; сохраняется single-use семантика.
- Добавлены network regressions миграции и расширены проверки multipart
  recovery, потерянных ответов, отмены запросов и конфликтов destination.

Настройка, команды миграции, recovery и ограничения отката:
[docs/HTTP-UPLOAD.md](docs/HTTP-UPLOAD.md).

Команды, результаты и границы подтверждения, включая qualification реального
object store и 10 GiB: [docs/VALIDATION-0.7.9.md](docs/VALIDATION-0.7.9.md).

Итог: 265 тестов, нагрузка 500 TLS клиентов и native reference — успешно.
Реальные 10 GiB через MinIO (описанный test adapter), 1280parts и полный SHA-256
пройдены; подробности — [VALIDATION-0.7.9](docs/VALIDATION-0.7.9.md).
