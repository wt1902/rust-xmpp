# Журнал сервера и диагностика авторизации — 0.7.4

После сборки/перезапуска строка `starting`/`ready` должна показывать 0.7.4.
Это позволяет проверить, что запущен новый binary/container image.
Без настройки журнал пишет info/warn/error в stderr (виден в Docker logs).

Для диагностики одной попытки входа добавьте в Lua-конфиг:

```lua
log = { debug = "*console" }
log_format = "json"
```

В JSON-конфиге это поля `global.log = {"debug":"*console"}` и
`global.log_format = "json"`. Обычный текст: `log_format = "plain"`.
`debug = true` включает debug по умолчанию, если `log` не задан.
Настройки наследуются из global, локальный `log` VirtualHost имеет приоритет.

Файлы в стиле Prosody:

```lua
log = {
    info = "/var/log/prosody/rust-xmpp.log";
    error = "/var/log/prosody/rust-xmpp.err";
    debug = "*console";
}
log_format = "plain"
```

Каталоги должны существовать и быть доступны UID процесса. Файлы открываются
append с правами 0600. Level-map включает указанный уровень и старшие уровни.
Explicit sinks поддерживают диапазон и точный набор уровней:

```lua
log = {
    { to = "file"; filename = "/var/log/prosody/debug.log";
      levels = { min = "debug"; max = "warn" } };
    { to = "console"; levels = { "error" } };
}
```

`levels = "warn"` в explicit sink — только warn, как у native loggingmanager.
`log = "*console"` и `log = { "*console" }` включают debug и старше.
Дополнительное сокращение runtime `log = "debug"` также пишет debug в консоль.
Вся строка JSON/plain записывается под общим mutex, ID не смешиваются.

Файлы ротируются внешним logrotate: после rename отправьте процессу SIGHUP.
Журнал переоткроет destinations и запишет `logs-reopened`. При ошибке
переоткрытия старые файловые дескрипторы сохраняются. SIGHUP здесь не означает
горячую перезагрузку конфигурации или Lua-модулей. Автоматической ротации и
retention нет. Native syslog sink, mixed Lua tables, timestamp templates и
произвольные plugin sinks пока не реализованы.

## Как собрать одну попытку

В JSON есть `timestamp`, `level`, `module`, `connection`, `event`, `fields`.
`connection` — случайный ID одного transport, не SM resume token. Поля в
`fields` — массив `{key,value}`, который можно преобразовать через jq
`from_entries`. Проследите один ID от `connection-open` до `connection-closed`:

1. `connection-open`: host, transport, peer.
2. `tls-established`: фактическая версия TLS и cipher.
3. `sasl-features`: объявленные механизмы, CB-типы, account_hash и SSDP.
4. `sasl-attempt`: номер попытки, механизм, SASL1/SASL2.
5. `account-lookup`: нормализованный user, hash и состояние записи.
6. `sasl-challenge`, затем `auth-success` либо `sasl-rejected`.
7. `resource-bound`/`session-resumed`, затем `connection-closed`.

При закрытии есть phase, reason, duration_ms и io_kind. Если клиент отключился
после challenge, сервер видит только `phase=sasl-client-final` и disconnect;
его внутреннюю причину (например, локальное отклонение SSDP) сервер узнать
не может. Для этого потребуется клиентский журнал. Для HTTP adapter peer
помечается not-forwarded: внутренний duplex не получает адрес HTTP-запроса.

| Событие/причина | Что проверять |
|---|---|
| account-lookup: missing-or-disabled | Правильный host, data_path/volume, наличие и enabled-состояние аккаунта |
| account-record-invalid | Lua account record повреждён или не поддержан |
| account-hash-or-record-invalid | stored/server key length и настроенный SHA-1/SHA-256 должны соответствовать |
| invalid-client-proof | Proof не проверилась: пароль, устаревшие credentials либо несовместимый расчёт клиента; это не доказательство конкретно неверного пароля |
| channel-binding-mismatch | Выбранный CB не соответствует данному TLS-сеансу/сертификату |
| channel-binding-downgrade-detected | Клиент отправил y при доступном серверном CB |
| mechanism-not-offered | Клиент выбрал механизм, которого нет в sasl-features |
| invalid-authzid | Authorization identity не совпадает с нормализованным владельцем |
| client-aborted-after-challenge | Клиент явно отменил обмен; wire-ответ aborted |
| inline-request-malformed | Ошибка Bind2/resume, поле detail уточняет класс |
| bind-rejected/resource-conflict | Авторизация прошла, проблема уже на этапе ресурса |

Дополнительно пишутся listener-ready, resource-replaced, session-disconnected
(removed/hibernating и unacked count), session-expired, maintenance-failed,
базовые открытия/закрытия входящих S2S и shutdown-requested. Это начальное
покрытие операций, не полная замена всех журналов модулей Prosody.

В журнал не передаются пароли, соль/ключи, SASL base64, nonce/proof, resume/push
токены и XML/тела сообщений. Имена аккаунтов и peer-адреса присутствуют для
диагностики, как в Prosody. Дополнительный фильтр редактирует sensitive field
keys; escaping исключает вставку новых строк/control characters в запись.

Нужен фрагмент одной неуспешной попытки Conversations/monocles, включая version
и перечисленные события. До получения этого фрагмента причина конкретного
оставшегося отказа на вашей установке не установлена.

## Изменения 0.7.1

Одинаковые console destinations (включая aliases) и одинаковые строки путей
файлов объединяются с union уровней; overlapping rules не создают дубликаты.
Разные destinations получают независимые копии записи согласно своим уровням.

`sasl-attempt` теперь записывается до inline validation. `sasl-inline-options`
содержит только requested/available flags без payload. Необъявленный cached
Bind2/SM логируется как `inline-request-ignored` с причиной bind2-disabled или
sm-disabled и fallback=post-auth-stream-features. Это не ошибка пароля.
Malformed enabled inline extensions сохраняют rejection и более точный detail.

## PEP/PubSub в 0.7.2

INFO pubsub-iq-result содержит классифицированные action/node_kind/status/condition,
precondition_not_met и счётчик deliveries. Для disco — pep_identity,
persistent_items, publish_options. Идентификаторы устройства/элемента/запроса,
полные имена узлов и payload не печатаются. WARN iq-dispatch-failed содержит
безопасный io_kind. Значение deliveries не доказывает получение клиентом.
Интерпретация ошибок и проверка после обновления — PEP-DIAGNOSTICS.md.

## Содержимое результата PEP в 0.7.3

`target_scope` классифицирует цель запроса без её адреса. У successful items
result `items_count` — число непосредственных item, `first_content_kind` —
известный класс первого payload или none/other/nested-item, `first_device_count`
— количество непосредственных device в распознанном списке первого item.
Никаких значений device ID или bundle bytes. Это структура XML, не проверка
валидности ключей, доверия или числовых ID. Для других операций этих счётчиков нет.
`implicit` означает отсутствие to; сам по себе он не утверждает выбор аккаунта.

## HTTP и PEP0.7.4

HTTP diagnostics: listener-ready, connection-open, tls-established,
request-complete route/status, connection-closed phase/reason. Routes ограничены
websocket/bosh/other; raw URLs, queries, Origin/headers/bodies не пишутся.
Для подключения Converse: CONVERSE-WSS.md.

PEP IQ: device_protocol legacy/omemo2/other, valid_device_count и
invalid_device_count. notification-generated: content_present и такие же
счётчики локально созданного сообщения ДО routing, не подтверждение доставки.
ID/JID/ключевые данные не добавляются. Подробности — PEP-DIAGNOSTICS.md.
