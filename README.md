# Rust XMPP 0.8.0

Сервер на Rust, разрабатываемый для замены **Prosody 13.0 nightly 100,
cafd74b9c5ea** с предоставленными модулями. Читает существующий Lua-конфиг,
а также JSON, YAML/YML и TOML. Использует внутреннее файловое хранилище
Prosody: конвертация аккаунтов и истории для проверенных сценариев не нужна.
Nginx не требуется: HTTPS, WebSocket, BOSH и загрузка файлов обслуживаются
самим сервером; coturn остаётся отдельным сервисом.

Это работающая экспериментальная реализация, **полная взаимозаменяемость
ещё не достигнута**. Уже реализованы вход, сообщения, контакты, MAM, MUC,
PEP/pubsub, закладки, offline, carbons, SM, push, TLS-федерация и HTTP.
Точные ограничения перечислены в [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md),
проверки — в [docs/VALIDATION.md](docs/VALIDATION.md).

Нестандартные HTTP-пути и TLS reverse proxy: [docs/HTTP-PROXY.md](docs/HTTP-PROXY.md).
Пример для слияния с действующим конфигом: `examples/reverse-proxy.fragment.yaml`.

MUC и восстановление после сбоя, включая SM resume:
[docs/MUC-RECOVERY.md](docs/MUC-RECOVERY.md).
Изменения 0.8.0: [CHANGELOG-0.8.0.md](CHANGELOG-0.8.0.md).

Встроенный http_altconnect: [docs/HTTP-ALTCONNECT.md](docs/HTTP-ALTCONNECT.md).

## Сборка и изолированный запуск

Нужны Rust 1.99.1 (rustup установит версию из `rust-toolchain.toml`),
C-компилятор и make. Для тестовых сертификатов и сетевых проверок нужны
OpenSSL CLI, Bash и Python 3; HTTP-тест дополнительно использует Python `websockets`.
Системные CA-сертификаты нужны для проверки удалённых серверов федерации.
Cargo.lock фиксирует зависимости; первая сборка требует их загрузки.

```bash
cd rust-xmpp
cargo build --release --locked
bash scripts/make-demo.sh
./target/release/rust-xmpp serve demo/config.toml --experimental
```

Demo слушает только `127.0.0.1:55222` и создаёт отдельное хранилище `demo/data`.
Аккаунты: `alice@localhost / alice-test-only` и
`bob@localhost / bob-test-only`. Для ручного клиента используйте STARTTLS
и доверьте сгенерированному `demo/cert.pem`. `make-demo.sh` не перезаписывает
существующий demo. Сертификаты и аккаунты в исходный архив не включены.

## Существующий конфиг без редактирования

```bash
./target/release/rust-xmpp check-config /etc/prosody/prosody.cfg.lua
./target/release/rust-xmpp serve /etc/prosody/prosody.cfg.lua --experimental
```

`check-config` проверяет разбор и базовые типы; ограничения runtime проверяются
при `serve`. Существующий Lua-файл читается непосредственно, преобразовывать
его в другой формат не требуется. Процессу нужны права на сертификат, ключ,
каталог данных и Unix admin socket. Используйте тот же UID/GID, что и Prosody,
чтобы сохранять доступ при возврате к нему.

Первую проверку выполняйте на копии данных с отдельными портами: сервер пишет
аккаунты, историю, комнаты и другие данные в обычном режиме. Одновременно
запускать Rust и Prosody с одним каталогом данных нельзя. Между экземплярами
Rust действует блокировка inode каталога данных, в том числе при разных портах
и путях-синонимах. Prosody в этой блокировке не участвует. Команда create-user
также отказывается писать в каталог работающего Rust-сервера; для изменения
аккаунтов во время работы используйте admin shell. Для переключения остановите один процесс и запустите
другой. Резервная копия нужна для проверки отката до переключения рабочего
сервера; тестирование формата не доказывает совместимость всех ваших записей.

## Ваш Docker Compose

Распакуйте каталог `rust-xmpp` рядом с исходным `docker-compose.yml`.
Дополнительный файл заменяет образ только сервиса `prosody`. Порты, тома,
healthcheck `prosodyctl check` и сервис coturn наследуются из исходного файла.

```bash
docker compose -f docker-compose.yml -f rust-xmpp/compose.override.yml config
docker compose -f docker-compose.yml -f rust-xmpp/compose.override.yml up -d --build prosody
```

Эта команда запускает сервер на томах из исходного Compose; применяйте её
после проверки на копии. Исходные `docker-compose.yml` и `prosody.cfg.lua`
редактировать не требуется. Образ содержит CA-сертификаты и команду
`prosodyctl`, совместимую с указанным healthcheck. Это проверка ответа
работающего процесса через admin socket, а не полный аналог диагностики
`prosodyctl check`.

Entrypoint определяет UID/GID владельца `/var/lib/prosody` и запускает процесс
с этими правами, не меняя рекурсивно владельцев существующих файлов. Если
каталог принадлежит root, а файлы внутри другому UID, задайте `XMPP_UID` и
`XMPP_GID` в окружении контейнера через дополнительный Compose-файл.
При другом пути данных задайте также `XMPP_DATA_DIR`. Выбранный пользователь
должен читать TLS-ключ и писать данные. Docker-образ в среде разработки
не собирался: здесь нет Docker; состав образа и override подготовлены,
но запуск на целевом Docker ещё предстоит проверить.

## Форматы конфигурации

Все форматы используют одну структуру: `global` и `hosts`; у хоста есть
`options` и, для компонента, `component`. Надёжнее получить её из Lua:

```bash
./target/release/rust-xmpp convert /etc/prosody/prosody.cfg.lua json config.json
./target/release/rust-xmpp convert /etc/prosody/prosody.cfg.lua yaml config.yml
./target/release/rust-xmpp convert /etc/prosody/prosody.cfg.lua toml config.toml
./target/release/rust-xmpp check-config config.yml
```

Конвертер сохраняет области настроек и Include, не меняет исходный файл,
не перезаписывает существующий выходной и создаёт его с правами `0600`.
Выходной файл содержит секреты конфигурации. Lua выполняется в ограниченной
VM без системных библиотек; произвольные Lua-плагины не исполняются.
Поддержка Lua в проекте также нужна для точного чтения файлов данных Prosody.

## Команды и проверки

Полный локальный прогон: `bash scripts/verify-local.sh`.
`XMPP_LOAD_CHECK=1` добавляет нагрузочный сценарий; настройки native Prosody
для дополнительных проверок описаны в `scripts/prosody_compat/README.md`.

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
python3 scripts/smoke.py                    # после make-demo.sh
python3 scripts/integration_xmpp.py
python3 tests/sasl_network.py --spawn --hash sha1
python3 tests/sasl_network.py --spawn --hash sha256
python3 tests/sasl2_bind.py target/release/rust-xmpp
python3 scripts/integration_http.py         # требует websockets
python3 scripts/load_smoke.py --clients 500 --accounts 100 --rounds 10 --message-rounds 10 --archive
```

Все сетевые тесты создают отдельные тестовые данные; кроме smoke с портом
55222, выбирают свободные loopback-порты. Оригинальная Prosody отдельно
проверяет формат данных и пароли: инструкции в
[scripts/prosody_compat/README.md](scripts/prosody_compat/README.md).

```bash
./target/release/rust-xmpp create-user CONFIG USER --password-stdin
./target/release/rust-xmpp check [CONFIG]
./target/release/rust-xmpp shell CONFIG 'server:status()'
```

Пароль `create-user` принимает через stdin; существующий аккаунт не заменяет.
Admin shell реализует ограниченный набор команд управления сервером и
аккаунтами. Произвольный Lua-код и горячая перезагрузка модулей не поддержаны.

## Дополнительный SASL2 Bind2

Модуль `sasl2_bind2` (alias `bind2`) включает привязку ресурса внутри SASL2,
inline SM/CSI/Carbons и MAM metadata. Добавьте его в modules_enabled вместе
с `sasl2` только если эта функция нужна. Исходный конфиг по-прежнему работает
без включения нового модуля. Ресурс генерируется случайно; прежние соединения
того же аккаунта с тем же валидным UUIDv4 user-agent завершаются после успешного
входа. Inline возобновление SM через SASL2 поддерживается, в том числе после
перезапуска при наличии действующей сохранённой SM-сессии.

## PEP, push и pre-authenticated roster

В 0.5.0 исправлены ответы disco для bare JID аккаунта. При включённых
`pep` и `cloud_notify` (они уже есть в предоставленном конфиге) изменение
конфига не требуется. После обновления переподключите аккаунт в клиенте,
чтобы повторить service discovery. Push требует также настройки
клиентского push-сервиса; реальный APNs/FCM шлюз здесь не имитируется.

При включённом `roster` клиент может обнаружить и вызвать контактную
ad-hoc команду `urn:xmpp:invite#invite` на серверном JID. Она возвращает
`xmpp:…?roster;preauth=…` и срок действия. Регистрацию аккаунта такое
приглашение не разрешает. XEP-0379 presence tokens сохраняются даже
для неизвестных серверу приглашений, созданных самим клиентом.

## Переподключение в 0.6.0

Повторная привязка одного ресурса по умолчанию заменяет старое соединение,
как в Prosody. `conflict_resolve` поддерживает `kick_old`, `kick_new`,
`increment` и `random`. Если явно задан `kick_new`, занятый ресурс по-прежнему
получит protocol conflict — это выбранная политика.

SM восстанавливается при гонке со старым TCP и внутри SASL2. Исправлено
освобождение ресурсов при BOSH/WebSocket close. Подробности:
[CHANGELOG-0.6.0.md](CHANGELOG-0.6.0.md).

## Android SASL в 0.6.1

Добавлен `tls-server-end-point` для TLS1.2/1.3 и исправлена SSDP-проверка
соединений WebSocket без channel binding. Причина воспроизводимого
`not-authorized` в Conversations, область тестирования и ограничения
описаны в [CHANGELOG-0.6.1.md](CHANGELOG-0.6.1.md) и
[docs/ANDROID-SASL.md](docs/ANDROID-SASL.md).

## Логирование в 0.7.0

Добавлены журнал TLS/SASL/bind/SM с единым connection ID, точные причины
отказов, файлы/console, JSON/plain и SIGHUP rotation reopen. Для диагностики
Conversations/monocles используйте [docs/LOGGING.md](docs/LOGGING.md).

## Исправления 0.7.5

Cached SASL2 Bind2/SM requests допускают legacy fallback, XEP-0258/0077
объявляются для Gajim; policy/classifications схема может использоваться
как каталог labels. Дубликаты одинаковых log destinations устранены.
Подробности — [CHANGELOG-0.7.5.md](CHANGELOG-0.7.5.md).

## HTTP Upload в 0.7.9

Несколько upload components с разными HTTP hosts или mounts и S3-compatible
gateway с multipart streaming описаны в [docs/HTTP-UPLOAD.md](docs/HTTP-UPLOAD.md).
Добавлены offline миграция с SHA-256/resume, точечная очистка multipart и
карантин неопределённого completion. Реальные 10 GiB через MinIO проверены с
описанной адаптацией тестовой среды. Изменения и границы подтверждения —
[CHANGELOG-0.7.9.md](CHANGELOG-0.7.9.md).

## MUC и SM после сбоя в 0.8.0

MUC фиксирует конфигурацию, роли, членство и ограниченную историю без MAM
до публикации соответствующего ответа. Последний сохранённый журнал позволяет
восстановить persistent и временные комнаты после аварийной остановки.
Heartbeat обновляет живое состояние; срок уже ожидающего восстановления
не продлевается повторным запуском. `muc_recovery_grace_period` задаётся
в секундах: по умолчанию 300, пределы 1..604800.

Действующие приватные SM-записи восстанавливают логические сессии и MUC
до открытия listeners, поэтому offline-доставка может попасть в сохранённую
очередь. XEP-0198 resume через legacy SASL или SASL2 требует нового
TLS/SASL-транспорта и токена того же владельца; TCP/TLS-сокеты не сохраняются.
Без действующей SM-записи MUC ожидает новую аутентификацию точного полного JID
и available presence либо обычный явный MUC-вход.

Native-файлы экспортируются для Prosody; источником согласованного crash
recovery Rust служит собственный журнал. Перед откатом ознакомьтесь с
[порядком переключения](docs/MUC-RECOVERY.md). Произвольные community Lua-модули
не выполняются; неизвестные явно включённые MUC-модули отклоняются при запуске.
Результаты проверки — в
[docs/VALIDATION-0.8.0.md](docs/VALIDATION-0.8.0.md).

## GitHub Actions и Gitea Registry

Полные тесты, Linux binary artifact и Docker push после проверок:
[настройка workflow](docs/GITHUB-ACTIONS.md). Registry и credentials задаются
через GitHub Actions variables/secrets.
