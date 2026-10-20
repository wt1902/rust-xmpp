# DNSSEC и индикатор monocles

Проверено 2026-10-20 UTC. Выполнены только чтение исходников клиентов и
публичные DNS-запросы; DNS-зона, регистратор и production не изменялись.
Приложения на Android не запускались.

## Что именно показывает клиент

В monocles `EditAccountActivity.java` выбирает `not_dnssec_verified`, если
нет соединения или `XmppConnection.resolverAuthenticated()` возвращает false.
Последний метод возвращает `currentResolverResult != null &&
currentResolverResult.isAuthenticated()`. Проверка DANE отдельная и выполняется
только внутри положительной ветки DNSSEC; наличие TLS-сертификата само по себе
не делает этот индикатор положительным.

В обычном пути SRV + IP (`Resolver.resolveIpsAsFuture`) флаг равен
`SRV.isAuthenticData() && addressResult.isAuthenticData()`. Для hostname-only
fallback достаточно authentic SRV; для пути без SRV monocles переносит authentic
флаг A/AAAA. MiniDNS сначала пытается проверить DNSSEC через DNS текущей сети,
при ошибках может перейти к обычному DNS. Поэтому даже после корректного
подписания зоны результат зависит от версии приложения и DNS сети телефона.
Ручной hostname (`fromHardCoded`) устанавливает authenticated=true без DNSSEC;
его нельзя использовать как доказательство подписи зоны или как исправление DNSSEC.

Эти детали относятся к проверенному monocles master. В проверенном Conversations
master DNS-запросы выполняются через AndroidDNSClient, а `ResolverResult` создаётся
с null DNSSEC metadata; нельзя автоматически переносить поведение индикатора между
версиями и форками клиентов.

## Публичная зона wthome.ru

Google DNS JSON API с `do=1` дал следующие результаты:

| Запрос | Результат |
| --- | --- |
| `wthome.ru DS` | NOERROR, без DS в Answer |
| `wthome.ru DNSKEY` | NOERROR, без DNSKEY в Answer |
| `_xmpp-client._tcp.wthome.ru SRV` | `5 0 5222 wthome.ru.` |
| `_xmpps-client._tcp.wthome.ru SRV` | NXDOMAIN |
| `wthome.ru A` | `88.204.18.107` |

Во всех этих ответах `AD=false`; у ответов зоны wthome.ru нет RRSIG.
Cloudflare DNS JSON API независимо подтвердил отсутствие DS. Совокупность
результатов указывает на неподписанную зону без цепочки доверия из .ru,
а не на ошибку SASL или отсутствие XMPP stream feature. Это снимок DNS на дату
проверки, а не постоянная гарантия состояния зоны.

## Что нужно настроить оператору

1. Включить DNSSEC у авторитетного DNS-провайдера зоны, убедиться, что DNSKEY и
   RRSIG опубликованы и действительны. Если текущий тариф/провайдер этого не
   поддерживает, сначала перенести зону с сохранением всех записей.
2. Получить DS из реально работающего подписанного ключа и опубликовать его
   через регистратора в родительской зоне .ru. Не придумывать DS вручную и не
   публиковать DS до готовности подписанной зоны.
3. Проверить валидатором цепочку root → ru → wthome.ru и подписи SRV + A/AAAA
   фактически используемого target. Для target в другой зоне проверить и её
   цепочку. Дождаться обновления DNS-кэшей.
4. Переподключить клиент через DNS-сеть, передающую нужные DNSSEC-записи, проверить
   его resolver log и индикатор. Отдельный DANE-индикатор потребует корректных
   TLSA и их DNSSEC-проверки; для одного DNSSEC-индикатора TLSA не обязателен.

Диагностика с установленным BIND tools:

```sh
dig +dnssec wthome.ru DS
dig +dnssec wthome.ru DNSKEY
dig +dnssec _xmpp-client._tcp.wthome.ru SRV
dig +dnssec wthome.ru A
delv _xmpp-client._tcp.wthome.ru SRV
delv wthome.ru A
```

`+dnssec` только запрашивает записи DNSSEC и само по себе не проверяет подписи;
для проверки нужен валидирующий resolver или delv. Обычный DoH AD=false тоже
не различает все причины отсутствия проверки без анализа DS/DNSKEY/ответов.

## Почему это не исправляется кодом c2s-сервера

Клиент проверяет DNS до TCP/TLS/XMPP. Сервер не может передать ему DNSSEC-флаг
через XML, SASL2, Bind2 или TLS. Текущий `src/federation.rs` использует
`TokioAsyncResolver::tokio_from_system_conf()` только для исходящего s2s SRV;
Cargo.toml не включает dnssec feature Hickory. Проверка TLS при этом использует
JID-домен назначения, а не неподтверждённый SRV target. Добавление DNSSEC в s2s
resolver было бы отдельной задачей и не исправит DNSSEC-индикатор Android-клиента.

## Источники и воспроизводимость

Исходники прочитаны с mutable master; commit pin для этих загрузок не подтверждён.
Пути внутри `src/main/java/eu/siacs/conversations/`:

- https://codeberg.org/monocles/monocles_chat — `ui/EditAccountActivity.java`,
  `utils/Resolver.java`, `xmpp/XmppConnection.java`.
- https://codeberg.org/iNPUTmice/Conversations — `utils/Resolver.java`.
- https://dns.google/resolve?name=wthome.ru&type=DS&do=1
- https://dns.google/resolve?name=wthome.ru&type=DNSKEY&do=1
- https://dns.google/resolve?name=_xmpp-client._tcp.wthome.ru&type=SRV&do=1
- https://cloudflare-dns.com/dns-query?name=wthome.ru&type=DS
  (заголовок `Accept: application/dns-json`).

SHA256 прочитанных Java-файлов:

- `monocles-AccountActivity.java`: `96af8f891a8e6dbf647c34e07a19dd6782aeeba3fa6ec2de5d6b3332121ce56d`
- `monocles-Resolver.java`: `890856ea1221cf09aa951612e6fce2f27d2aea5c5e7c03b27af0a9a8d5977e79`
- `monocles-XmppConnection.java`: `37a2cd5c62242b47eaab5023c48807870428a053cbc1586408ba51e1b8dee6fd`
- `conv-Resolver.java`: `892bc1a346102798dc502bfa8c4c061a2f5fec7bffde1b4c78fba45d4383557b`
