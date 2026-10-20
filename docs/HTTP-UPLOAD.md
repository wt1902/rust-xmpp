# HTTP File Upload (0.7.9)

XEP-0363 component `http_file_share` выдаёт slots через XMPP и обслуживает
HTTP PUT/GET/HEAD. Доступны локальные файлы и S3-compatible object storage.
В S3-режиме RustXMPP работает как gateway: клиент получает URL component,
а сервер подписывает запросы к bucket по AWS Signature Version 4. Это не
выдача клиенту S3 credentials или presigned bucket URLs.

## Несколько components

Каждый component сохраняет собственные XMPP JID, discovery, размер файла,
квоты, slots, JWT secret, backend и HTTP mount. HTTP-маршрут выбирается по
`Host` и `http_paths.file_share`. Можно использовать разные HTTP hosts с
одинаковым mount либо один host с непересекающимися mounts:

```lua
-- Добавьте к существующей конфигурации; сохраните VirtualHost, TLS и модули.
Component "upload.example.org" "http_file_share"
    http_host = "files.example.org";
    http_paths = { file_share = "/personal"; }
    http_file_share_backend = "local";
    http_file_share_size_limit = 10737418240; -- 10 GiB
    http_file_share_daily_quota = 21474836480;
    http_file_share_global_quota = 107374182400;
    http_file_share_expires_after = "7d";

Component "media.example.org" "http_file_share"
    http_host = "files.example.org";
    http_paths = { file_share = "/media"; }
    http_file_share_backend = "local";
    http_file_share_size_limit = 104857600;
```

Для одного effective HTTP host одинаковые или вложенные mounts отвергаются
при startup с сообщением `ambiguous HTTP upload components`, содержащим
имена обоих components и пути. Например, `/files` конфликтует с `/files`
и `/files/private`; `/files` и `/files-other` не конфликтуют. Mount `/`
пересекается со всеми mounts этого host. Hosts сравниваются без учёта
регистра; порт в HTTP Host не выбирает отдельный component.

WebSocket, BOSH и `http_altconnect` используют общие HTTP listeners вместе
с uploads. Их маршруты обрабатываются соответствующим middleware. Выделяйте
uploads собственные mounts, чтобы действующие transport/discovery endpoints
не перекрывали публичные адреса загрузки.

`http_external_url` задаёт публичную базу, сохраняя внутренний mount.
`http_file_share_base_url` явно переопределяет полный публичный upload prefix.
При reverse proxy настройте переписывание пути и передавайте правильный Host:
одного изменения рекламируемого URL недостаточно для настройки proxy.
Пример конфигурации proxy — [HTTP-PROXY.md](HTTP-PROXY.md).

## S3-compatible backend

```lua
Component "upload-s3.example.org" "http_file_share"
    http_host = "files.example.org";
    http_paths = { file_share = "/objects"; }
    http_external_url = "https://files.example.org";
    http_file_share_backend = "s3";
    http_file_share_size_limit = 10737418240;
    http_file_share_daily_quota = 21474836480;
    http_file_share_global_quota = 107374182400;
    http_file_share_s3 = {
        endpoint = "https://objects.example.org";
        bucket = "xmpp-uploads";
        region = "us-east-1";
        access_key_env = "RUSTXMPP_S3_ACCESS_KEY";
        secret_key_env = "RUSTXMPP_S3_SECRET_KEY";
        -- Только для временных credentials:
        -- session_token_env = "RUSTXMPP_S3_SESSION_TOKEN";
        key_prefix = "upload-s3";
    }
```

Переменные должны присутствовать в окружении процесса сервера при startup,
например через защищённый EnvironmentFile службы. Их отсутствие вызывает
ошибку startup. Доступны и строковые поля `access_key`, `secret_key`,
`session_token`; соответствующее поле `*_env` имеет приоритет. Credentials
не включаются в сохранённую backend identity.

Endpoint использует path-style bucket addressing. HTTPS требуется для
нелокальных S3 endpoints. HTTP допускается только для `localhost` или
loopback IP, например `http://127.0.0.1:9000` в изолированном тесте.
Production endpoint должен иметь сертификат, доверенный системным root CAs.
Не путайте HTTPS object-store endpoint с публичным HTTPS upload URL:
оба соединения настраиваются независимо. Для публичных клиентов используйте
HTTPS listener либо существующий TLS reverse proxy с HTTPS advertised URL.

Bucket должен разрешать создание multipart upload, загрузку частей, завершение,
abort, `ListMultipartUploads` (`s3:ListBucketMultipartUploads`), HEAD/GET
и удаление объектов для retention.
Перед CreateMultipartUpload сервер сохраняет intent для принадлежащего ему
slot. Если ответ с UploadId потерян, recovery перечисляет multipart uploads
с pagination и прерывает только uploads с полным совпадением object key;
соседние keys с тем же prefix не затрагиваются. Сохранных native metadata,
подтверждающих владение slot, достаточно и для legacy records без intent или
UploadId. Cleanup такого slot не зависит от bucket lifecycle.

Lifecycle `AbortIncompleteMultipartUpload` рекомендуется как дополнительная
защита, например при утрате metadata или внешних orphan uploads. Он не даёт
абсолютной гарантии очистки; scope, сроки и выполнение правил зависят от
object store. Не запускайте внешних writers с теми же slot keys: cleanup
предполагает исключительное владение ими.

Gateway передаёт файл частями по 8 MiB и ограничивает число одновременно
активных S3 uploads восемью на component. Файл целиком не буферизуется в памяти и не
сохраняется во временный локальный файл. Служебная память, TLS/HTTP buffers
и буфер текущего входящего frame добавляются к памяти частей; ограничение
не является гарантией точного общего RSS. Ограничение размера применяется
и к chunked PUT, а квоты учитывают зарезервированные slots component.

## Metadata, recovery и смена credentials

XMPP upload metadata остаются в native хранилище `uploads` и `upload_stats`
в `data_path`. S3 заменяет хранение содержимого файлов, а не XMPP metadata.
Сохраняйте `data_path` вместе с bucket: один bucket не восстанавливает
владельцев, quotas и slots. В `rust_uploads.json` сохраняются служебное
состояние slots, completion, multipart intent и незавершённые UploadId;
файл не заменяет native архив. `rust_upload_backend.json` фиксирует backend identity.

Перед открытием listeners сервер восстанавливает незавершённые S3 records:
прерывает принадлежащие slot multipart uploads, затем проверяет удалённый
объект и размер и учитывает уже завершённый commit. Ошибка обязательного
recovery, кроме quarantine completion, останавливает startup. Перед
CompleteMultipartUpload сохраняется `completion_attempted`. Если результат
completion неизвестен и после cleanup
HEAD ещё возвращает 404, только этот slot остаётся в quarantine: PUT возвращает
409, retention его не удаляет, остальные slots и startup продолжают работу.
Maintenance каждые 60 секунд повторяет сверку; подтверждённый объект
ожидаемого размера снимает quarantine и завершает recovery. Неопределённый
результат требует сверки оператором с object store, если объект так и не
появился. Корректный явный S3 completion error допускает повтор после
reconciliation; network/timeout или некорректный ответ не разрешают
перезапись возможного позднего commit. Ошибки обязательных listing/HEAD
по-прежнему останавливают startup.
PUT остаётся single-use; повторная запись завершённого slot возвращает conflict.

При наличии slots нельзя незаметно переключить local/S3 backend, endpoint,
bucket или prefix: startup отвергает изменение backend identity. Добавление
S3 к существующим local slots также требует явной миграции через offline CLI,
описанный ниже; не удаляйте identity-файл для обхода проверки.

Для rotation S3 credentials обновите переменные окружения/секреты службы
и перезапустите сервер, сохранив endpoint, bucket и prefix. Новая identity
credentials не содержит, поэтому их rotation не считается миграцией.
Сначала обеспечьте новым credentials доступ к существующим объектам и
multipart cleanup. Rotation `http_file_share_secret` — отдельная операция:
смена JWT signing secret делает ранее выданные PUT tokens недействительными.

## Offline миграция local ↔ S3 и S3 ↔ S3

Остановите RustXMPP и Prosody, использующие этот `data_path`, и сохраните
резервную копию metadata и содержимого backend. Подготовьте две полные
конфигурации: `current.cfg.lua` описывает действующий source, `new.cfg.lua` —
destination. Обе должны содержать тот же VirtualHost, upload component,
`data_path`, HTTP/HTTPS ports, публичные маршруты и `http_file_share_secret`;
меняйте только параметры backend. Credentials обоих S3 хранилищ должны быть
доступны CLI; используйте отдельные переменные окружения для source и
destination. Для каждого component выполняется отдельная команда:

```sh
# План: без копирования объектов, изменения journal или backend identity.
rust-xmpp upload-migrate current.cfg.lua new.cfg.lua --component upload.example.org

# Копирование и проверка; при остановке повторите эту же команду.
rust-xmpp upload-migrate current.cfg.lua new.cfg.lua --component upload.example.org --execute

# После сообщения Migration committed запускайте сервер с новой конфигурацией.
rust-xmpp serve new.cfg.lua --experimental
```

Команда захватывает exclusive lock `data_path`, исключающий параллельный
RustXMPP или другую миграцию; Prosody этот lock не использует. Source и
destination должны иметь разные backend identities. Поддерживаются local →
S3, S3 → local и S3 → другой endpoint, bucket или prefix. Перед миграцией
восстановите незавершённые uploads исходным сервером. Dry run проверяет
конфигурации и metadata и определяет объекты для копирования; полный SHA-256
рассчитывается при `--execute`.

Копируются завершённые файлы, включая native файлы без Rust completion
sidecar и файлы, опубликованные перед сбоем записи completion cache.
Отсутствующие незавершённые reservations остаются в metadata. Native
`uploads`, `upload_stats`, владельцы, slots и JWT не переписываются.
Source objects никогда не удаляются. Для каждого файла CLI проверяет размер,
считает SHA-256 source и повторно читает destination для сверки; ETag не
используется как checksum. Существующий destination с другим содержимым
вызывает отказ без перезаписи.

Миграция обрабатывает файлы последовательно через приватный временный файл:
нужно свободное место размером максимум в один переносимый файл дополнительно
к постоянному local destination. Память ограничена buffers частей, файл
целиком в RAM не загружается. После сбоя временный spool удаляется и текущий
файл читается заново; это возобновление по объектам, не по byte offset.

`rust_upload_migration.json` хранит identities, fingerprint metadata,
checksums и прогресс. Повторный запуск с теми же конфигурациями сверяет source
и уже скопированные файлы, восстанавливает multipart cleanup и продолжает
работу. Backend identity переключается только после проверки всех объектов.
Незавершённый или повреждённый journal блокирует startup до offline recovery,
даже если component убран из новой конфигурации. Не удаляйте journal для
обхода барьера и не редактируйте metadata во время миграции.

Сохранённый source позволяет сверить данные и подготовить откат, но простая
подмена конфигурации после commit отвергается identity guard. Пока migration
не завершена, продолжите её с теми же параметрами. После commit выполняйте
обратную offline миграцию с текущей конфигурацией как source и прежней как
destination. Новые uploads могли появиться только в destination; откат к
старой резервной копии без их переноса потеряет эти изменения. Конфликтующие
объекты обратная миграция также не перезаписывает. Удаление прежнего source
после проверки результата — отдельное решение оператора.

## Проверки и границы подтверждения

`tests/upload_multi_network.py` проверяет настоящий binary через TLS XMPP
и HTTP: отдельные/shared hosts, discovery и IQ slots, квоты, изоляцию JWT,
PUT/GET и restart, а также композицию с WS/BOSH/host-meta и отказ при
неоднозначных mounts.

`tests/upload_large_network.py` выполняет opt-in передачу полного файла по
проверяемому HTTPS с local backend и записывает измерения в JSON. Для default
10 GiB необходимо более 10 GiB свободного места. Это отдельная проверка от S3
fixture, и её результат не подтверждает передачу 10 GiB в object store.

`tests/upload_s3_network.py` использует независимый локальный HTTP fixture,
который повторно вычисляет SigV4 и реализует S3 protocol для проверки gateway,
multipart, чтения и обработки ошибок. Это не qualification на AWS S3,
MinIO или другом production object store. Их совместимость требует отдельного
запуска в целевой среде.

`tests/upload_migration_network.py` проверяет offline миграцию с независимым
SigV4 fixture: local ↔ S3, S3 ↔ S3, dry run, прерывание/возобновление,
checksums, сохранность source и native metadata, блокировку startup.

`tests/upload_minio_network.py` — opt-in запуск с настоящим MinIO executable.
По умолчанию он передаёт 10 GiB через HTTPS gateway в MinIO, проверяет полный
GET и SHA-256, multipart, Range, restart и crash cleanup. Малый `--size`
проверяет smoke path, но не подтверждает передачу большого объекта.

Итоговые команды, результаты и измерения release validation публикуются в
[release validation report](VALIDATION-0.7.9.md). Предыдущий результат 10 GiB
с local backend, SHA-256, Range за 4 GiB и выборочным RSS опубликован в
[отчёте 0.7.8](VALIDATION-0.7.8.md); сам по себе он не подтверждает S3 backend.


В 0.7.9 фактические 10 GiB HTTPS PUT/GET через MinIO успешно пройдены: 1280
multipart parts, SHA-256 совпал, Range/restart/crash cleanup проверены.
MinIO собран из upstream release с test-only fallback перечисления интерфейсов
на loopback при EPERM; S3/auth/storage code не менялся. Точный diff и hashes
в VALIDATION-0.7.9.md. Немодифицированный MinIO/AWS/distributed deployment этим
не сертифицируются. MINIO_BINARY перед verify-local.sh включает opt-in 10 GiB
прогон; для обычной среды используйте собственный MinIO executable.
