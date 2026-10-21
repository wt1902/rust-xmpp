# 0.8.3 — durable IO личных сообщений

- Уменьшено число последовательных синхронизаций до доставки: ordinary MAM
  append использует один sync вместо четырёх, SM checkpoint — один вместо двух.
  Checksummed redo journals сохраняют commit-before-ACK и восстанавливают
  native archive/SM JSON exports после аварии.
- Ограничены рост журналов, ротация и tombstone GC. Старый `.rappend` и legacy
  JSON импортируются. Retain/save/purge не возвращают удалённые записи.
- Recovery синхронизирует валидный journal перед публикацией состояния; проверка
  checksum не заменяет durability barrier. EIO при adoption блокирует startup
  или offline handoff. Новые fault fixtures проверяют сохранность журнала и retry.
- Replay SM проверяет checksum/JSON всех frames, но создаёт и валидирует полный
  Record только для последнего snapshot, сокращая работу с superseded queues.
- `message-processing-slow` содержит времена MAM отправителя/получателя,
  доставки, carbons, offline/push и handled, а также число ресурсов/копий.
  Payload и секреты не добавляются в логи.
- Добавлена offline команда `storage-checkpoint CONFIG`: durable экспорт и
  передача archive writer/подготовка отката на legacy Rust. Не запускайте другого
  writer и не удаляйте journals до успешного завершения команды.
- Новые crash, partial-write, corruption, EIO, recovery, handoff и latency
  регрессии включены в GitHub Actions через verify-local.sh; отчёты сохраняются.

Измерения, ограничения и эксплуатация:
[docs/DURABLE-MESSAGE-IO.md](docs/DURABLE-MESSAGE-IO.md),
[docs/VALIDATION-0.8.3.md](docs/VALIDATION-0.8.3.md).
