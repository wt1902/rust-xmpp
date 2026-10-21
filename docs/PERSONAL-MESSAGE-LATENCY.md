# Личные сообщения: исправления0.8.2

Предыдущий0.8.1 устранил per-message MUC archive scan и часть лишних CSI writes.
Отдельная проверка личных чатов обнаружила другие причины. Испытания ниже
проведены на loopback; это не подтверждение поведения конкретной production-сессии.

## Push не должен останавливать чат

В прежнем обработчике после локальной доставки выполнялся await внешнего
push IQ route и только потом обновлялся handled и читалось следующее сообщение.
Неполадки DNS/TCP/TLS/SASL внешнего шлюза задерживали отправителя до сетевого
таймаута (30с на route). При полностью offline получателе push даже отправлялся
раньше записи offline archive.

Регрессия воспроизвела настоящий исходящий STARTTLS к шлюзу, который после TLS
не присылает features. У0.8.1 через2с первое сообщение уже в durable SM pending,
второго нет, SM ACK отсутствует. У0.8.0 с полностью offline получателем в этот
момент ещё нет даже первого offline record. В0.8.2 в обоих сценариях оба сообщения
сохранены и sender ACK h=4 соответствует входящим4 stanza при том же зависшем
шлюзе. Offline records присутствуют уже при первом post-TLS stream gateway.

Уведомления теперь маршрутизирует ограниченный worker:1024queued,8in-flight.
При переполнении/ошибке notification routing пишет warning; подтверждение
сообщения не означает успешный push. Очередь уведомлений не durable и при
остановке отменяется; сами сообщения сохраняются независимо. Проверен XMPP
push fixture, не APNs/FCM и не промышленный мобильный цикл.

## CSI и зашифрованные сообщения без body

Прежняя policy считала unimportant receipt-only и ciphertext-only OMEMO без
body/EME. При `inactive` они могли ждать активности клиента. В тесте намеренный
dwell2с показан отдельно: это время удержания, не вычислительная задержка.
Сервер уже быстро отвечал SM ACK, но пользователь ещё не видел payload/receipt.

Default `csi_important_payloads` в0.8.2:

- `{eu.siacs.conversations.axolotl}encrypted`
- `{urn:xmpp:omemo:2}encrypted`
- `{urn:xmpp:receipts}received`
- `{urn:xmpp:chat-markers:0}received`
- `{urn:xmpp:chat-markers:0}displayed`
- `{urn:xmpp:chat-markers:0}acknowledged`

Они выходят без ожидания active. Body, EME и остальные прежние important payload
сохраняют поведение; headline и прочие unimportant данные продолжают буферизоваться.
Явный список заменяет defaults: если уже настроили свой список, добавьте нужные
пути туда. Для строгой прежней policy в JSON используйте `csi_important_payloads: []`;
эквивалентный явно непустой Lua-list без новых extensions:
`csi_important_payloads = { "{urn:xmpp:eme:0}encryption" }` (EME уже important).
Defaults увеличивают число немедленных доставок и возможных пробуждений клиента.
Старая importance function/native oracle сохранена; изменён именно runtime default.
На bind и resume применяется текущая конфигурация, включая сохранённые старые slots.

В6TLS fixtures:100000MAM/user, roster0/5000/10000,500durable pending, default/explicit[]:
все проверки прошли. Default inactive OMEMO legacy/2 —2.58–4.06мс,
receipts —7.36–35.56мс; при explicit[] сохраняется hold до active.
Headline buffering, EME delivery и точный счёт100523MAM records/user проверены.
Это XML/wire проверка доставки ciphertext, не проверка OMEMO криптографии клиента.

## Большой личный архив при входе

Bind2 и обычный MAM metadata IQ раньше декодировали все записи ради start/end.
На100000records,5samples:

| Операция | Старая медиана |0.8.2медиана |
|---|---:|---:|
|SASL2 Bind2 authenticate→success|2742.353мс|1.976мс|
|TCP/STARTTLS→Bind2 success|2745.115мс|3.565мс|
|MAM metadata IQ|2437.945мс|0.355мс|

Baseline0.8.0 содержит тот же прежний scan path; hash сохранён в raw report.
Новый edges_store читает ограниченные endpoint records под существующей блокировкой,
не создаёт/не требует index и восстанавливает partial append. Проверяются exact
IDs/timestamps. Это операция metadata, не проверка integrity всех промежуточных
записей. Полные MAM queries и периодическая очистка всё ещё могут читать архив.

## Проверка и диагностика

Новые scripts:

```bash
python3 tests/push_latency_network.py --binary target/release/rust-xmpp --recipient hibernating
python3 tests/push_latency_network.py --binary target/release/rust-xmpp --recipient offline
python3 tests/personal_message_latency_network.py --binary target/release/rust-xmpp
python3 tests/bind2_archive_latency_network.py --binary target/release/rust-xmpp --records 100000 --samples 5
```

Быстрые варианты включены в verify-local.sh и CI. Push fixture использует
loopback port5269; конфликт порта является ошибкой fixture. Global DNS/resolv.conf
не меняются; fixture использует special-use localhost и другой account domain.

`message-processing-slow` warning содержит duration_ms, route и correlation connection.
Оно фиксирует завершившуюся серверную обработку>250мс, без текста сообщения.
Если задержка остаётся, сопоставьте его с клиентским временем, типом transport,
CSI state, регистрацией push и внешней федерацией. Отсутствие warning не доказывает
отсутствие сетевого/клиентского ожидания до/после обработки.

SM Store пока использует общий mutex для durable slot IO; обязательный fsync
не отключён. Полные архивные запросы/maintenance, большие roster, медленный диск
и внешняя федерация имеют собственную стоимость. Производственная квалификация
клиентов и полная замена Prosody остаются за рамками этих fixtures.
Итоговые тесты/сырые отчёты: VALIDATION-0.8.2.md и validation-logs-0.8.2/.
