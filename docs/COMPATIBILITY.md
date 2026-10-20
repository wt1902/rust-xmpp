# Совместимость с предоставленной установкой

Цель — конкретная Prosody `cafd74b9c5ea` и предоставленные community/custom
модули ревизии `dddb6c34b964`, а не все существующие модули Prosody.
Известные встроенные и выбранные модули предоставленной установки отображаются
на обработчики Rust. Произвольные Lua/community-модули не исполняются;
неизвестные явно включённые MUC-модули отклоняются при запуске.
Это не означает полного совпадения поведения с Prosody.

| Область | Что реализовано | Существенные пределы |
|---|---|---|
| Конфигурация | Lua/JSON/YAML/YML/TOML, Include, глобальные и локальные области, наследование модулей | Lua VM ограничена; не все функции окружения конфигуратора Prosody доступны. Runtime обслуживает один VirtualHost и его компоненты |
| Хранилище | internal `.dat`, `.list`, бинарные строки, смешанные ключи Lua, атомарные записи, потоковые архивы, инвалидирование `.lidx` | SQL, external storage остальных модулей и произвольные драйверы не реализованы; S3 uploads поддержаны. Каталог блокируется между процессами Rust; Prosody в блокировке не участвует |
| Аккаунты, saslauth | internal_hashed SHA-1/SHA-256, SASLprep, PLAIN внутри TLS, SCRAM и PLUS с tls-exporter/tls-server-end-point, SSDP, SASL2 | Только internal_hashed; опциональный sasl2_bind2 (alias bind2) поддерживает inline bind/SM/CSI/Carbons. SASL2 inline SM resume и takeover живого транспорта реализованы; MAM metadata при Bind2 читает весь архив синхронно |
| Сообщения и presence | локальная маршрутизация, приоритеты ресурсов, контакты/подписки/probes, offline, carbons, блокировки | Полная совместимость всех пограничных сценариев маршрутизации ещё не подтверждена |
| MAM | личный и комнатный MAM2, prefs, формы, RSM, фильтры времени/контакта/ID, extended queries, metadata, stanza-id, expiry | Нет доказательства совпадения каждой ошибки и порядка результатов при всех комбинациях запроса |
| MUC | комнаты, несколько ресурсов, роли/affiliations, owner/admin, конфигурация, приглашения, история без MAM и MAM, occupant-id/avatar, hats, PM/presence policies, регистрация, административные ad-hoc команды; журнал конфигурации, членства и истории до ответа, crash recovery persistent/temporary комнат | Rust-журнал авторитетен, native config/state — экспорт. Без SM восстановление требует новой аутентификации точного полного JID; grace по умолчанию 300 с, `muc_recovery_grace_period` 1..604800. Действующая приватная SM-запись восстанавливает логическое членство до listeners. Произвольные Lua-модули не запускаются; [MUC-RECOVERY.md](MUC-RECOVERY.md) |
| PEP/pubsub | persistent nodes/items, ACL, subscriptions, publish/retract/purge/delete, owner/configuration, caps, OMEMO XML как payload | Не все необязательные политики узлов Prosody реализованы; OMEMO шифруют клиенты, криптография OMEMO не часть сервера |
| private/bookmarks/vCard | private XML, старые и новые закладки, vCard/temp-vCard4 и avatar-переходы | Межклиентное поведение нужно дополнительно проверить настоящими клиентами |
| SM/push | acknowledgements после обработки, resumable XEP-0198 sessions, replay, ограниченные очереди, приватный durable snapshot, heartbeat и shutdown checkpoint; legacy SASL/SASL2 resume после restart; native регистрации push | Нужны новый TLS/SASL-транспорт и токен того же владельца; TCP/TLS-сокеты не сохраняются. SM-снимок не native Prosody: 256 MiB суммарно, 8 MiB/4096 stanza на сессию. При неопределённой отправке возможен replay. Есть coalescing и watchdog первого push; реальный APNs/FCM цикл не подтверждён |
| CSI | active/inactive, ограниченный буфер, native importance rules, delay, flush при клиентской активности и grace period | Событие socket drain приближено завершением записи; необязательные расширенные XPath-фильтры поддержаны не полностью |
| Федерация | входящие/исходящие STARTTLS, CA/DNS-ID, SASL EXTERNAL, DNS SRV, проверка домена каждого stanza, ограниченный пул соединений | Нет dialback/DANE/OtherName-only/SRV-ID/bidi/direct TLS |
| HTTP upload | Несколько XEP-0363 components, Host/path isolation, local/S3 gateway, multipart/SigV4, streaming PUT, GET/HEAD/range/conditional, квоты/expiry, native metadata/JWT; offline local↔S3/S3↔S3 migration с SHA-256/resume; intent/exact-key recovery и quarantine; реальный 10 GiB PUT/GET через MinIO проверен | MinIO single-node с описанным netlink adapter тестовой среды; AWS/distributed deployment не проверены. Миграция требует остановки сервера и временного места под один файл; source сохраняется. Потерянные ownership metadata и неопределённый Complete требуют отдельного разбора; HTTP-UPLOAD.md |
| WebSocket/BOSH | WS/WSS и HTTP/HTTPS, общая XMPP-сессия, origin rules, BOSH RID/retry/hold/reorder/restart; http_altconnect XRD/JRD discovery; http_paths, HTTP Host/fallback, внешний URL, доверенные IP/CIDR и forwarded headers для TLS reverse proxy | Один VirtualHost с компонентами; нет PROXYv1/v2, произвольных Lua HTTP-приложений и горячей перенастройки. См. HTTP-PROXY.md |
| admin_shell | протокол admin socket, status/version/uptime, списки, основные операции аккаунтов | Нет произвольного Lua, горячей загрузки модулей и полного набора prosodyctl |
| Остальные модули | disco, ping, time, version, uptime, register, TURN extdisco/HMAC, каталог seclabels | Нет встроенного TURN. Coturn работает отдельно. `pep_simple` пуст в предоставленном исходнике |

## Особенности именно вашего конфига

- `allow_registration = true` действительно разрешает регистрацию, несмотря
  на противоречащий этому комментарий в исходном файле.
- Личная история настроена `never`, комнатная — на неделю. Очистка выполняется
  периодически; append не переписывает весь архив.
- Лимит отдельного файла — 10 GiB, общий — 100 GiB. В 0.7.8 фактические
  HTTPS PUT/GET 10 GiB с local backend проверены с совпадением SHA-256,
  Range за 4 GiB и выборочным RSS. В 0.7.9 дополнительно проверены 10 GiB через
  MinIO single-node с описанным adapter тестовой среды; см. VALIDATION-0.7.9.md.
- Структура `security_labels.default_policy/policies/classifications` отличается
  от native `mod_seclabels`. С0.7.1 её точная schema может использоваться как
  catalog metadata: выбранный default_policy и его classifications. ACL и
  обязательное enforcement не реализуются; неизвестные поля отвергаются.
- Настройки `limits` сами по себе не включают `mod_limits`; он не указан
  среди включённых модулей исходного конфига и не является autoload-модулем
  предоставленной Prosody. В этой реализации транспортного rate limiting пока нет.
- Чужие Lua-плагины из каталога `custom_plugins` автоматически не запускаются.
  Наличие исходников 479 каталогов не означает, что все они были включены.

## Что осталось для утверждения «полная замена»

Нужны подтверждённый запуск на копии реальных данных, проверки настоящими
Monal/Conversations/Gajim и используемым push-шлюзом, совместимость с внешними
XMPP-доменами и сертификатами, проверка целевого Docker/UID/TLS, откат, долгий
нагрузочный прогон и устранение оставшихся различий из таблицы.
Текущие автоматические проверки покрывают конкретные сценарии и не заменяют
эти критерии. Проект намеренно сохраняет флаг `--experimental`.

## Исправления discovery и pre-auth в 0.5.0

PEP описывается identity `pubsub/pep` на bare JID аккаунта. Push feature
`urn:xmpp:push:0` возвращается на собственном bare JID при включённом
`cloud_notify`, в том числе без PEP. Серверный JID остаётся `server/im`.
PEP leaf nodes сохраняют `node`, собственные ACL и ошибки отсутствующего узла.
Функции MAM, блокировок и другие account features не теряются в раннем PEP reply.

С `roster` доступны RFC6121 subscription preapproval и контактная часть
XEP-0379/XEP-0401: ad-hoc `urn:xmpp:invite#invite`, одноразовые токены
с истечением срока, автоматическое подтверждение и обратная подписка.
Неизвестный клиентский preauth сохраняется при пересылке и в pending presence,
чтобы владелец мог подтвердить подписку вручную или в своём клиенте.

Нет приглашений на создание/сброс аккаунта и landing page; `ibr=y` не выдаётся.
Unscoped токены используют native per-user `invite_token` map; scoped токены
хранятся отдельно, чтобы Prosody без поддержки scope не мог выдать лишние права.
Токен потребляется до нескольких roster-записей: при дисковой ошибке между
записями нет multistore rollback, ошибка передаётся вызывающему коду, токен
повторно автоматически не авторизует подписку. Возможен ручной fallback.

## Переподключение в 0.6.0

`conflict_resolve` следует native sessionmanager: default/kick_old, kick_new,
increment и random. Новая привязка отзывает прежний resume token при замене;
она не наследует старые SM acknowledgements. Успешный resume сохраняет SM,
Carbons, push identifier и очередь, изолируя старый transport от нового состояния.

BOSH terminate ждёт engine cleanup, WebSocket close/EOF закрывает input и
даёт engine завершиться перед ограниченным timeout abort. Сетевой тест
использует kick_new, чтобы случайное hibernation не скрылось takeover-политикой.

## Android SASL в 0.6.1

На TLS1.2 предлагается certificate endpoint binding, на TLS1.3 также exporter.
Проверены SHA1/256, SASL1/2, SSDP on/off, tampered bindings, WSS без CB и
явно отключённый PLUS. Monocles имеет версионные различия fallback; настоящие
устройства не запускались. Certificate signature algorithms EdDSA/unknown
не используются для endpoint binding; TLS1.3 exporter при этом сохраняется.

## Логирование в 0.7.0

Native-style log level maps и explicit sinks, console/file, JSON/plain, UTC
millis и SIGHUP reopen реализованы. В scope входят TLS/SASL/bind/SM, startup,
maintenance и основные входящие S2S события. Syslog/plugin sinks, mixed Lua
log tables, полный hot reload и журналы всех модулей не реализованы.
PLAIN теперь нормализует имя/authorization identity; wire abort/retry проверены
отдельно. Журнал нужен для диагностики оставшегося реального Android отказа.

## Cached SASL2 и Gajim в 0.7.1

Bind2 остаётся явно включаемым. Сохранённый Quickstart request к недоступному
optional extension не мешает credentials exchange и последующей обычной
привязке. Inline SM при отключённом smacks также не обрабатывается.
Host/account discovery объявляет seclabels/register по наличию реальных
обработчиков; создание новых аккаунтов по-прежнему зависит от allow_registration.
Gajim predicates проверены по python source, реальные приложения не запускались.
Policy catalog adapter — расширение для supplied config, а не ACL implementation.

## PEP и DNSSEC в 0.7.2

Добавлены проверки OMEMO/аватаров с публикацией без to, recoverable missing
bundles, publish-options/config retry, сохранением после restart и скрытой
от журнала полезной нагрузкой. IQ errors адресуются от имени исходной цели;
notification defaults совпадают с эффективной конфигурацией при preconditions.
Конкретный production IQ отказ из INFO-лога0.7.1 неизвестен.
DNSSEC клиент проверяет до XMPP; текущая зона wthome.ru не имеет обнаруженных
DS/DNSKEY. Требуется настройка DNS/регистратора, docs/DNSSEC.md. Эта сборка не
добавляет DNSSEC validation в outbound federation.

## PEP порядок в 0.7.3

PEP/PubSub items выдаются newest-first, как реальный supplied mod_pep.
Протокольный regression сохраняет старую пустую и новую populated devicelist,
проверяет первый item как Android parser, замену current и restart. Native
oracle отдельно подтверждает порядок. Это не гарантирует исправления каждого
production индикатора: реальная конфигурация/содержимое узлов не предоставлены.

## HTTP и диагностика0.7.4

HTTPS учитывает https_interfaces (включая* → IPv4+IPv6), HTTP — http_interfaces,
с fallback к interfaces. Добавлена безопасная HTTP/TLS/status диагностика.
Закрытие до SASL обрабатывается штатно и завершает WebSocket. Для подтверждённой
страницы Converse https://conversejs.wthome.ru добавлен точный allowed Origin
в примеры; рабочий конфиг требуется обновить отдельно. Runtime wire test
подтверждает original403 → configured101, IPv4/IPv6 и TLS validation.
PEP production причина по-прежнему не доказана; новая диагностика различает
parser-valid IDs и форму уведомлений. Нет подтверждения Android UI, живого
production WSS, DNSSEC signing или полной замены Prosody.

## Восстановление MUC и SM в 0.8.0

MUC-журнал хранит последнее согласованное поколение конфигурации, ролей,
членства и ограниченной истории, включая временные комнаты без MAM.
Неудачная фиксация откатывает изменение комнаты; внешний MAM-архив и прочие
побочные эффекты не составляют единую транзакцию с журналом. Heartbeat обновляет
живое состояние, но не продлевает deadline уже ожидающих записей.

При действующей сохранённой SM-сессии bootstrap восстанавливает логическую
сессию и связанное MUC-членство до начала приёма соединений. Offline-доставка
попадает в SM-очередь, а не в несуществующий сокет. Для сетевого resume нужны
новая TLS/SASL-аутентификация и действующий токен владельца. Без такой SM-записи
действует обычное повторное подтверждение полного JID и MUC admission.

Учтены `muc_max_rooms`, `restrict_room_creation`,
`allow_unaffiliated_register`, `enforce_registered_nickname`,
`muc_registration_include_form`, `muc_tombstone_expiry` и component-admin
ad-hoc destroy/set-affiliation. Общие и host `modules_disabled` применяются
к vCard и occupant-id. Эти встроенные обработчики не запускают Lua-плагины.
Ограничения журнала, native-экспорта и отката:
[MUC-RECOVERY.md](MUC-RECOVERY.md). Итоги проверки:
[VALIDATION-0.8.0.md](VALIDATION-0.8.0.md).
