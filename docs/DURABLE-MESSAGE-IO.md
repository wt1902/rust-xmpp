# Личные сообщения и durable IO в 0.8.3

В присланном журнале сервера 0.8.2 есть три `message-processing-slow` с 4792–5549 мс,
route=local. Этот таймер начинается после приёма XML и заканчивается после
`mark_handled`: ожидание происходит внутри обработчика. Старые события не
содержат разбивки по этапам и сами по себе не доказывают причину медленного IO.
Исходный пользовательский журнал не включён в архив проекта.

## Изменение записи

До 0.8.3 append в MAM требовал 4 последовательных sync: rollback marker file+dir,
native list, удаление marker+dir. Обычное сохранение SM требовало 2: JSON file+dir.
В TLS fixture1:1 с двумя аккаунтами, четырьмя SM-ресурсами и carbons это обычно
16 sync на сообщение. Увеличение задержки каждого настоящего fsync/fdatasync
внутри изолированного data_path воспроизводит задержку в несколько секунд.
Interposer не пропускает sync и не меняет системные настройки/production.

В 0.8.3 принятые данные сначала фиксируются в журнале восстановления с checksum:

- MAM `.rredo`: native `.list` сохраняет формат Prosody; обычный append требует
  одного sync журнала. Replay восстанавливает недостающий native suffix и
  отбрасывает незавершённый хвост. Полностью записанная повреждённая запись
  вызывает ошибку. Ротация —128 frames/1 MiB плюс максимум одна 16 MiB запись.
- SM `.wal`: authoritative полные snapshots и tombstones; readable JSON —
  восстанавливаемый экспорт. Обычное сохранение требует одного sync_data.
  Ротация —16 MiB плюс максимум один snapshot; aggregate WAL cap 512 MiB,
  logical slots по-прежнему 256 MiB/8 MiB на slot/4096 stanzas и 4096 sessions.
  Tombstone GC сначала синхронизирует удаление JSON, затем удаляет WAL.

Recovery синхронизирует полностью проверенный журнал перед публикацией
восстановленного состояния: полный frame после SIGKILL может остаться
только в page cache. Checksum подтверждает целостность, но не запись на диск. Ошибка этого sync запрещает startup/handoff.

Создание журналов, восстановление и ротация дополнительно синхронизируют файлы
и каталог. Экономия относится к обычной записи, не каждому возможному запросу.
Отключения durability или периодической записи вместо commit-before-ACK нет.
При неопределённой ошибке SM IO store блокирует дальнейшие изменения до
восстановления. После успешного WAL commit ошибка экспорта не откатывает память.
Queues/archives не образуют общей транзакции с сетью: гарантия replay остаётся
at least once, а не exactly once между всеми хранилищами.

## Передача данных Prosody и откат версии

После SIGKILL/OS crash сначала используйте 0.8.3 для восстановления redo. Не
удаляйте `.wal`/`.rredo` вручную и не редактируйте JSON export как источник истины.
Для смены writer или отката на старую версию остановите сервер и выполните:

```bash
rust-xmpp storage-checkpoint /etc/prosody/prosody.cfg.lua
```

Команда берёт data-directory lock и SM store lock, восстанавливает журналы,
синхронизирует native archives и актуальные JSON, затем durably удаляет redo.
При ошибке передача владения не завершена; разберите ошибку, не запускайте
другой writer. Перед работой с production данными сохраните обычную резервную
копию всего data_path. Native Prosody не понимает resumable SM snapshots Rust;
checkpoint SM обеспечивает совместимый JSON для старого Rust, не переносит
TLS/TCP/SM-сессию в Prosody. Простой graceful stop не заменяет эту явную команду.
Нельзя одновременно изменять `.list` средствами Prosody и Rust. Неjournaled
in-place append при активном redo считается незавершённым и может быть отброшен.
При восстановлении согласованной копии всего data_path журнал остаётся
авторитетным независимо от смены inode файла. Любая внешняя модификация,
включая atomic replacement, требует handoff. Внутренний rewrite сначала
фиксирует старый native snapshot и удаление redo, затем атомарно заменяет native
файл: авария в промежутке сохраняет старый snapshot, после замены — старый/новый.
Редактирование baseline in place без handoff не поддержано. Anchor проверяет
последние 4 KiB baseline, не является checksum всего старого архива.

## Внешний перезапись baseline: «archive redo baseline changed in place»

Если какой-либо writer (бакап-восстановление, копия data_path, Prosody, старая
версия сервера) перезаписал native `.list` поверх зафиксированного baseline без
handoff, `.rredo` перестаёт совпадать со своим anchor. Каждый вызов
`archive_for_user` возвращал `Err`, и через `?` ошибка роняла session
(`connection-closed reason=protocol-or-transport-error`) — клиент (напр. Monal)
реконнектился по кругу, сообщение не доставлялось.

Начиная с 0.8.4 MAM-архивация на трёх местах личной доставки (отправитель,
получатель, входящая федерация) стала best-effort: при storage-ошибке исходная
stanza всё равно маршрутизируется, обе сессии остаются живы, в лог пишется
санитизированный `mam-archive-skipped`. Живой append остаётся fail-closed:
непроверенный журнал не удаляется молча, а сохраняется для явного handoff.

Ремонт выполняется той же командой offline handoff:

```bash
rust-xmpp storage-checkpoint /etc/prosody/prosody.cfg.lua
```

Теперь `prepare_rewrite` распознаёт непроверенный baseline (changed in place,
shorter, missing, journal exceeds bound), считает текущий durably-синхронизированный
native авторитетным, синхронизирует его и удаляет неприменимый журнал. После этого
MAM history снова читается, а новые append создадут свежий redo поверх нового
baseline. Сверку совместимости native-формата см. в исходниках Prosody
(`util/datamanager.lua` `list_append`/`list_store`, `plugins/mod_storage_internal.lua`
`archive:append`): Prosody пишет `item(...)` и при полной перезаписи применяет
atomic rename — что и меняет первые bytes baseline, оставляя Rust-журнал устаревшим.

## Диагностика

`message-processing-slow` по-прежнему имеет threshold 250 мс, duration_ms, route
и connection. Новые поля в integer milliseconds:

| Поле             | Измеряемый этап                                                      |
| ---------------- | -------------------------------------------------------------------- |
| pre_routing_ms   | Работа до личного MAM; для MUC/ранних выходов — обработка до handled |
| sender_mam_ms    | Политика и архивирование отправителя                                 |
| recipient_mam_ms | Проверка аккаунта, политика и архивирование получателя               |
| delivery_ms      | Маршрутизация, targets, mutex и transmit                             |
| carbons_ms       | Выбор ресурсов и отправка carbon                                     |
| offline_push_ms  | Offline commit и подготовка/enqueue push                             |
| handled_ms       | Session mutex и durable mark_handled                                 |

Неисполненные этапы равны 0. target_count — выбранные локальные ресурсы,
carbon_count — успешные carbon transmit. Это серверные этапы, не время
отображения клиентом. Тексты сообщений, SASL и токены не логируются.

## Проверки и границы

`tests/slow_storage_latency_network.py` — реальный STARTTLS, MAM/carbons/PEP,
контролируемый sync delay и счётчик операций. `tests/slow_storage_crash_network.py`
— sender SM ACK, немедленный SIGKILL, проверка committed journals/обоих архивов
до повторной аутентификации и replay всех ресурсов. Rust regressions проверяют
partial tails, corruption, ротацию, tombstones, migration и offline handoff.
Отдельный `journal_recovery_sync_network.py` вводит scoped EIO для WAL/redo
и проверяет отказ startup/handoff без потери journal и успешный повтор.
Точные измерения и результаты этой сборки — [VALIDATION.md](VALIDATION.md).

Общий mutex SM store, обязательное durable IO, большие pending snapshots,
полные MAM queries/maintenance, PEP storage и federation всё ещё имеют стоимость.
Медленный диск не становится быстрым от сокращения числа sync. Проверка на
loopback не устанавливает причину каждого production warning; новые phase
fields позволяют проверить это на целевой системе.
