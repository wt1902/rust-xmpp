# Источники проверки Android SASL
Проверено 2026-10-20. Java source использовался для анализа выбора механизма;
Android-приложения на устройстве не запускались. Python regression повторяет
выбор из Conversations, не всю реализацию приложения.

- https://xmpp.org/extensions/xep-0440.html (1.0.0)
- https://xmpp.org/extensions/xep-0474.html
- https://www.rfc-editor.org/rfc/rfc5929.html
- https://www.rfc-editor.org/rfc/rfc9266.html
- https://codeberg.org/iNPUTmice/Conversations
- https://codeberg.org/monocles/monocles_chat

Файлы fetched с mutable master. Следующие branch-head значения получены
после fetch; это не доказательство скачивания каждого файла по commit pin:

Retrieved 2026-10-20 UTC from mutable master; no commit pin confirmed.
https://codeberg.org/iNPUTmice/Conversations/raw/branch/master/src/main/java/eu/siacs/conversations/crypto/sasl/
API master commit observed after source fetch: bf3269cd128d4dbf0e479c091477fd9544a798b0
monocles master commit: 0bc8473a5d4597d1ffe5545055da692ef8b89d37

Локальные SHA256 загруженных исходников:

- ChannelBinding.java: 88723522ed5bb53e947ad7afbc8cd0f8712ea4747d847347c3e5cd7b9aa41389
- ChannelBindingMechanism.java: e8a492de0eb866fc93d673cbc46bd5fae18ecf4b7bb46e272e6dca9e8c086937
- DowngradeProtection.java: a3fe98c2ccad998deb46f5748411a1a26506215cabb2a4e1d7adce0f51f2ac03
- SaslMechanism.java: 9bec637e7d62cc86a7b09cb8353e6272c80fd7b5d94e305b936bcf8c5a611e73
- ScramMechanism.java: aa5b2cdc5389a12e8de8fef562f0ee2de45fbdf61fa8fdbd33ea63a5b9299ae8
- monocles-ChannelBinding.java: 88723522ed5bb53e947ad7afbc8cd0f8712ea4747d847347c3e5cd7b9aa41389
- monocles-ScramMechanism.java: fea3687a12260d9280e204cc003d689043654950118e2d1dc84c058c736234e7

Conversations selector предпочитает exporter только на TLS1.3, затем
unique на TLS≤1.2, затем endpoint. При отсутствии совместимого объявленного
типа старый путь использует NONE/y,,. Monocles master содержит дополнительный
continueWithoutChannelBinding с n,, и обязательным downgrade protection;
его поведение зависит от версии и не полностью моделируется Python тестом.

## Cached inline requests в 0.7.1

Полученный серверный журнал показывал TLS1.3 success и inline-request-malformed
до sasl-attempt. В server 0.7.0 строка `bind2 is disabled` не совпадала с
`Bind2 is disabled` в diagnostic mapper. В supplied конфигурации Bind2 явно
не включён. Quickstart constructor в клиентских XmppConnection.java использует
QUICKSTART_FEATURES, даже если на новом соединении Bind2 уже не объявлен.
Это воспроизведено новым tests/sasl2_cached_inline.py на binary0.7.0.

В0.7.1 unavailable optional bind/resume не отклоняет credentials exchange.
Bare authorization identifier и post-auth legacy bind позволяют клиентскому
fallback продолжить вход; available Bind2 работает по прежнему. Это решение
совместимости с фактическим client fallback, а не ссылка на явное MUST-ignore
из XEP-0388. Wrong password и malformed enabled extensions не разрешаются.

Источники: Conversations и monocles `src/main/java/eu/siacs/conversations/
xmpp/XmppConnection.java`, `im/conversations/android/xmpp/model/sm/Enable.java`,
полученные с mutable master 2026-10-20. Authentication success handler оставляет
isBound=false без bound, затем processSecureStreamFeatures делает обычный bind.
