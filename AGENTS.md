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

Версия Rust source — **0.8.0**. Последующие изменения добавили GitHub Actions,
Docker target для проверенного бинарника и этот handoff без изменения Rust source.
Перед передачей исходники упаковываются в ZIP; актуальный архив должен содержать
этот файл и `.github/workflows/ci.yml`. В среде ChatGPT сохраняйте новый архив
через доступный Library workflow, обновляя существующий проект, если его identity
известна. Не считайте scratch единственным долговременным экземпляром проекта.

## С чего начать

1. Прочитайте README.md, docs/COMPATIBILITY.md, docs/VALIDATION.md.
2. Для MUC/SM: docs/MUC-RECOVERY.md и CHANGELOG-0.8.0.md.
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
