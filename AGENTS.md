# Продолжение разработки Rust XMPP

## Цель и правила работы

Пользователь хочет заменить свою установку Prosody этим сервером на Rust.
Продолжайте реализацию и исправления самостоятельно в рамках текущего запроса:
воспроизводите проблему, исправляйте причину, проверяйте результат, обновляйте
документацию. Не ограничивайтесь планом, если доступна реализация.

- Общайтесь с пользователем по-русски, коротко сообщайте существенные результаты.
- Пользователь разрешил субагентов. Передавайте короткий самостоятельный brief,
  `fork_turns: "none"`, путь проекта, конкретную задачу, ограничения и проверку.
  Назначайте отдельные файлы владельцам; не допускайте конкурирующих правок.
- Сначала изучите актуальные файлы и незавершённые изменения. Не откатывайте
  чужую работу и не считайте предыдущую среду или набор инструментов неизменными.
- Не объявляйте полную совместимость с Prosody по результату ограниченных тестов.
  Сохраняйте `--experimental`, пока не выполнены критерии COMPATIBILITY.md.
- Не подменяйте реализацию рекламой disco features. Проверяйте реальный wire flow.
- Не пишите passwords, SASL payload, tokens, private keys в логи/отчёты/репозиторий.
- Production-конфигурацию, DNS и внешний registry меняйте только в рамках
  соответствующего задания и доступных полномочий. Не выдавайте локальные
  fixture-проверки за проверку реального клиента или production-сервера.

## Где находится проект

Корень — каталог с этим AGENTS.md, Cargo.toml и Dockerfile. В текущем workspace
это `/workspace/scratch/362577cdf2e0/recovered/rust-xmpp`; путь непереносимый.
В нём сейчас нет `.git`. Если следующая среда содержит Git checkout, используйте
его состояние и инструкции, не создавайте второй расходящийся источник истины.

Версия Rust source — **0.8.3**. В0.8.0 добавлены durable MUC/SM, затем CI
и этот handoff;0.8.1 исправляет задержку сообщений. См. docs/MESSAGE-LATENCY.md.
Перед передачей исходники упаковываются в ZIP; актуальный архив должен содержать
этот файл и `.github/workflows/ci.yml`. В среде ChatGPT сохраняйте новый архив
через доступный Library workflow, обновляя существующий проект, если его identity
известна. Не считайте scratch единственным долговременным экземпляром проекта.

## С чего начать

1. Прочитайте README.md, docs/COMPATIBILITY.md, docs/VALIDATION.md.
2. Для MUC/SM: docs/MUC-RECOVERY.md, CHANGELOG-0.8.0.md/0.8.1.md
   и docs/MESSAGE-LATENCY.md/PERSONAL-MESSAGE-LATENCY.md. Не возвращайте expiry scan архива на каждый append.
3. Для upload: docs/HTTP-UPLOAD.md, исторические VALIDATION-0.7.8.md/0.7.9.md.
4. Для CI: docs/GITHUB-ACTIONS.md, docs/CI-VALIDATION.md,
   `.github/workflows/ci.yml`, scripts/ci/verify-all.sh.
5. Выберите конкретный оставшийся пробел из COMPATIBILITY.md или текущей ошибки
   пользователя. Подтвердите его тестом до утверждения, что он исправлен.

## Карта исходников

- `src/server.rs`: runtime, TLS/SASL/bind, dispatch, доставка, запуск/остановка,
  MUC bootstrap для сохранённых SM-сессий.
- `src/sessions.rs`, `src/session_store.rs`, `src/csi.rs`: XEP-0198, очереди,
  durable slots, fencing, resume, CSI.
- `src/muc.rs`, `src/muc_recovery.rs`, `src/muc_history.rs`, `src/muc_admin.rs`:
  комнаты, журнал, восстановление, история и административные команды.
- `src/storage.rs`: native Lua storage, атомарные записи.
- Остальные подсистемы ищите по именам модулей; `rg` и `rg --files` предпочтительны.
- `scripts/verify-local.sh`: основной набор регрессий.
- `tests/*_network.py`: настоящие локальные TLS/HTTP/WS сценарии.
- `docs/validation-logs-*`: зафиксированные результаты конкретных прошлых сборок.

## Инварианты, которые нельзя потерять

### MUC

`rust_muc_checkpoint` — авторитетный согласованный журнал Rust: конфигурация,
affiliations, nick/роли/членство и ограниченная история, включая временные комнаты.
Изменение фиксируется до ответа/публикации; ошибка записи откатывает состояние.
Native config/state являются экспортом после commit. Устаревший native export
не должен возвращать старые права, nick или историю после аварии.

Без действующей приватной SM-записи восстановление требует новой аутентификации
точного полного JID и available presence либо явного MUC-входа. Текущие room ACL
проверяются повторно. Уже ожидающий recovery deadline не продлевается restart,
неудачной попыткой или восстановлением другого участника. Default grace300с;
`muc_recovery_grace_period` ограничен1..604800.

С действующей durable SM-сессией логическое членство восстанавливается **до
listeners**, после проверки аккаунта и room admission. Пока транспорт offline,
room fanout должен попадать в сохранённую SM-очередь. При bootstrap не отправляйте
синтетические join presence/history. Native MUC-файл сам по себе не является
доказательством доверенной SM-сессии.

Критическая регрессия: Alice возобновила сессию и отправила сообщение, Bob ещё
не аутентифицировался. Проверяйте сообщение в durable pending Bob ДО его входа.
Поздняя история при восстановлении может ложно показать успешную доставку.
См. tests/sm_restart_network.py.

### SM и доставка

SM snapshot приватный, atomic/fsync, с owner/token/fullJID/counters/pending/expiry.
Проверяйте owner и токен; старые connection handles не могут менять новую сессию.
Account deletion должна durably отозвать токены до purge. Повторно созданный
аккаунт не должен принимать старый токен. Удаление собственного аккаунта всё ещё
должно получить terminal IQ reply, несмотря на закрытую SM-сессию.

Handled увеличивается после обработки и только после SM enable. Подтверждения
и изменения очереди сохраняются до соответствующей отправки. Offline expiry
фиксирован; heartbeat обновляет только живой транспорт. Новый TLS/SASL обязателен:
сохранения TCP/TLS fd между процессами нет. Гарантия replay — at least once,
не exactly once между всеми хранилищами и сетью.

### Upload

Не разрушайте intent/exact-key multipart recovery, ownership isolation,
completion quarantine, атомарное чтение свежего snapshot при захвате claim и
source-preserving offline migration. HEAD404 после неопределённого Complete
не доказывает отсутствие удалённого commit. Подробности — HTTP-UPLOAD.md.

## Проверки

Toolchain задан rust-toolchain.toml: Rust1.99.1, rustfmt, Clippy.
Обычная проверка из корня:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
bash scripts/verify-local.sh
```

Изменения проверяйте подходящими тестами; не повторяйте дорогие неизменившиеся
сценарии без причины. Для итогового расширенного прогона:

```bash
XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh
```

Это ещё НЕ все ignored/large/native tests без дополнительных зависимостей.
Полный CI entrypoint — `scripts/ci/verify-all.sh`; ему обязательны
PROSODY_REFERENCE_SOURCE, PROSODY_REFERENCE_LUA и MINIO_BINARY. Он включает
native oracle/federation, обе нагрузки500TLS, AF_UNIX admin, archive>128MiB,
local и MinIO HTTPS PUT/GET10GiB. Нужны Lua5.4/native dependencies, OpenSSL и диск.
Точные команды установки и подготовки — workflow и scripts/ci/prepare-*.sh.

Bundled оригинальная Prosody cafd74b9c5ea:
`scripts/ci/vendor/prosody-cafd74b9c5ea.tar.gz`. Hash проверяется перед сборкой.
Не заменяйте её иной версией для получения зелёного native oracle.

В текущей среде native зависимости извлекались в `/tmp/xmpp-native/usr`:

```bash
export PATH=/root/.cargo/bin:$PATH
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export LD_LIBRARY_PATH=/tmp/xmpp-native/usr/lib/x86_64-linux-gnu
export LUA_PATH='/tmp/xmpp-native/usr/share/lua/5.4/?.lua;/tmp/xmpp-native/usr/share/lua/5.4/?/init.lua;;'
export LUA_CPATH='/tmp/xmpp-native/usr/lib/x86_64-linux-gnu/lua/5.4/?.so;;'
export PROSODY_NATIVE_PREFIX=/tmp/xmpp-native/usr
export PROSODY_REFERENCE_SOURCE=/workspace/scratch/362577cdf2e0/reference/prosody-cafd74b9c5ea
export PROSODY_REFERENCE_LUA=/tmp/xmpp-native/usr/bin/lua5.4
```

Эти пути — только подсказка для сохранившейся среды. На обычном CI зависимости
ставятся системно. Не используйте отсутствующий prefix как обязательное условие.
При прежнем сбое linker `memory map must have a non-zero length` помогало
`cargo clean -p rust-xmpp --release` перед повторной release-сборкой.
Не удаляйте бинарник, используемый параллельным тестом: нагрузочный тест теперь
копирует executable в отдельный каталог перед restart.

Полезные узкие проверки:

```bash
python3 tests/muc_crash_network.py target/release/rust-xmpp
python3 tests/sm_restart_network.py target/release/rust-xmpp
python3 tests/muc_sm_load_network.py --binary target/release/rust-xmpp --clients 500
```

Readiness timeout нагрузки увеличен до60с: восстановление500слотов заняло10.559с,
поэтому старые5с давали ложный failure. Не скрывайте реальный сбой увеличением
таймаута без диагностики. На перезапуске проверяйте доставку и counters, а не
только открытие порта.

## Что действительно проверено

Rust0.8.0:293 tests passed,11 ignored в обычном cargo test; native дополнительно
8module/storage+1federation. Все10 MUC crash cases прошли. Нагрузка:100аккаунтов,
500TLS SM-ресурсов,10комнат,25000join presence,1500message deliveries, SIGKILL и
resume10представителей. Результаты и ограничения — docs/VALIDATION-0.8.0.md.
Сводный успешный лог составлен из завершённых частей и повторной нагрузки после
исправления тестового readiness timeout; первоначальный failure сохранён отдельно.

10GiB local проверялся в0.7.8; MinIO в0.7.9 с раскрытой адаптацией EPERM при
перечислении интерфейсов. Не приписывайте эти старые передачи новой сборке.
CI собирает оригинальный MinIO без адаптации. AWS/distributed MinIO и настоящий
APNs/FCM/production client cycle не подтверждены.

GitHub workflow проверен actionlint1.7.7, shell/Python syntax и случаями tags.
Реального GitHub run, Docker build/run и Gitea push пока НЕ было: Docker daemon
здесь отсутствует, доступ к пользовательскому GitHub/Gitea не предоставлен.

## Исправление задержки0.8.1

Полный MUC archive expiry на каждом сообщении был причиной seconds-level latency:
100000records, median2518мс до →4.680мс после в realTLS loopback. Убраны no-op
CSI checkpoints и перезаписи неизменённых native exports; private account traffic
не ждёт MUC mutex. Обязательные durable commits сохранены. Четыре новые
структурные регрессии прошли; измерения содержат raw samples и binary hashes.
Результаты нового итогового прогона смотрите в docs/VALIDATION-0.8.1.md.
Старые293tests и10GiB цифры выше относятся к прошлым выпускам.

## Личная доставка0.8.2

Не await push gateway в обработчике личного сообщения: очередь1024/max8worker,
RAII cancellation при stop/error. Сначала durable offline/SM data, потомpush.
Runtime CSI defaults теперь включают OMEMO encrypted/receipts/markers; explicit
список заменяет defaults. Raw native importance function не менялась. Refresh
policy при resume нужен для старых persisted slots. Логmessage-processing-slow
не включает payload. Hub.for_owners выбирает account resources до session locks;
не возвращайте сканирование всех чужих session locks при deliver/carbons.
Archive.edges_store читает только endpoints для Bind2 и metadata IQ; сохранены
bounded Lua/recovery/locks, middle не проверяется этим metadata operation.
Новые тесты: personal_message_latency_network.py, push_latency_network.py,
bind2_archive_latency_network.py, archive_edges.rs, session_routing_isolation.rs.
Результаты текущей версии: docs/VALIDATION-0.8.2.md. Полный MAM query/maintenance
и глобальный mutex SM Store остаются возможными отдельными IO bottlenecks.

## Ближайшие задачи и границы

- Проверить первый настоящий CI run после загрузки репозитория и настройки
  GITEA_REGISTRY/GITEA_IMAGE variables и USERNAME/TOKEN secrets по инструкции.
  Registry push разрешён основной ветке и version tags только после всех тестов.
  Образ должен содержать тот же executable, что проверенный binary artifact.
- По новым сообщениям пользователя проверить реальные Conversations/Monocles,
  Monal/Gajim/Converse.js и целевой proxy/TLS. Старые жалобы PEP/DNSSEC не считайте
  закрытыми только потому, что локальный fixture зелёный. DNSSEC зоны требует
  отдельной проверки DNS/операторской конфигурации, не фиктивного server feature.
- Оставшиеся продуктовые пробелы перечислены в COMPATIBILITY.md: один VirtualHost,
  часть федерации/CSI/PEP, нет transport rate limiting, произвольных Lua plugins,
  SQL и полного prosodyctl. Выбирайте и проверяйте конкретные задачи.
- Для утверждения «полная замена» нужны реальные данные, внешняя федерация,
  настоящие клиенты/push, deployment/UID/TLS, rollback и длительная нагрузка.

После изменений обновляйте точные границы совместимости и результаты проверки.
Не перезаписывайте исторические отчёты как будто они относятся к новой сборке.
В передаваемый ZIP включайте AGENTS.md, workflow, vendor reference, исходники,
документацию и scripts; исключайте target, demo data, bin, .git, __pycache__, pyc
и секреты. Сохраняйте executable bits shell scripts и проверяйте содержимое ZIP.

## Durable message IO 0.8.3

Новый пользовательский log 0.8.2 содержит три local message-processing-slow
4792–5549 мс. Таймер начинается внутри server после XML, но старые поля не
доказывают причину IO. Контролируемый slow-sync fixture воспроизводит задержку
1:1 в несколько секунд. MAM 4 sync/append и SM 2 sync/checkpoint заменены
ограниченными checksummed redo journals. Обычная операция теперь требует 1 sync;
создание, recovery и rotation дороже. Точные результаты — VALIDATION-0.8.3.md
и DURABLE-MESSAGE-IO.md. Не приписывайте loopback причину production без phase logs.

SM `.wal` авторитетен, `.json` — readable export. Replay выполняется до JSON parse.
Неполный trailing frame отбрасывается; неполный baseline или полная corruption
блокируют startup. Durable tombstone предшествует delete. GC сначала делает
sync каталога с JSON deletions, затем unlink WAL и sync каталога.
Ordinary commit: append + sync_data, потом JSON export без sync. Ошибка export
после commit не откатывает память; store блокирует дальнейшие записи до recovery.
Precommit/sync error также блокирует store. Не возвращайте 2 sync на каждый
checkpoint и не удаляйте redo без checkpoint. Общий SM mutex пока сохранён.
Slot limit 8 MiB, total 256 MiB; WAL rotation 16 MiB плюс один slot, aggregate
512 MiB. Не допускайте роста каждого из тысяч slots без aggregate cap.

Archive `.rredo`: native baseline и bounded anchor, checksummed record frames.
Rotation после 128 frames/1 MiB плюс одна запись до 16 MiB. Cache ограничен 1024;
изменение metadata вызывает перепроверку. Accepted records восстанавливаются
даже при потере dirty native pages. Unjournaled native suffix не доказывает
external append: truncate до committed end. Legacy `.rappend` ещё восстанавливается.
Save/retain сначала durably фиксируют old native и удаление redo, затем
делают atomic replacement. Смена inode при копировании/backup НЕ отменяет redo: journal
остаётся авторитетным. Любой внешний writer, даже atomic replace, требует handoff. Purge включает rredo.
Recovery повторно инвалидирует `.lidx`: unlink на hot path отдельно не dirsynced.
Anchor проверяет только последние 4 KiB baseline, не всю старую историю.

Перед сменой writer/откатом остановите сервер и новым binary выполните
`rust-xmpp storage-checkpoint CONFIG`. Внешний data-directory lock обязателен.
`archive::checkpoint_all` и `session_store::checkpoint_exports` — только offline.
Сначала sync native/current JSON и каталога, потом remove journal и sync каталога.
Graceful stop сам по себе не означает handoff. Native Prosody не импортирует
Rust SM sessions. Не редактируйте JSON export для expiry fixtures: используйте
короткий настоящий timeout или проверяйте journal recovery. Не удаляйте WAL,
чтобы получить зелёный тест. Native oracle перед Prosody modification явно
вызывает checkpoint_all(root).

Новые tests: archive_redo.rs, sm_journal.rs, slow_storage_latency_network.py,
slow_storage_crash_network.py, journal_recovery_sync_network.py, fixtures/slow_sync.c. Interposer действует только
на изолированный fixture data_path. Обычный режим выполняет настоящий
fsync/fdatasync; отдельный XMPP_SYNC_FAIL_SUFFIX вводит EIO только для fault test.
Crash fixture проверяет journals и оба MAM архива до reauth после sender SM ACK
и SIGKILL. Readable JSON без redo не подтверждает durability. Phase fields —
server.rs и DURABLE-MESSAGE-IO.md.

В восстановленной среде native prefix теперь `/tmp/xmpp-native/usr/usr`, а не
старый `/tmp/xmpp-native/usr`. `/tmp/xmpp083-env.sh` содержит env текущего прогона;
это не portable config. Toolchain переустановлен; tests используют Rust 1.99.1.

Итог 0.8.3: 334 ordinary passed, 11 ignored; 9 native и 1 large-archive ignored
выполнены отдельно. Все network checks и обе нагрузки 500 TLS прошли.
Final binary SHA-256: 8ceb8de3a2d02bc4399b8ae817dff7e3c3fe9bff83dc0c6669b7f19210a3847a.
Подробные samples/границы — docs/VALIDATION-0.8.3.md. Checksum и JSON syntax всех frames
проверяются при SM replay, но Record создаётся только для последнего
snapshot. Recovery WAL sync до публикации обязателен; EIO fixture защищает это.
