# Клиентские признаки и проверки

Проверено 2026-10-20 по официальным XEP и исходнику Monal develop:
https://github.com/monal-im/Monal/blob/develop/Monal/Classes/MLIQProcessor.m

handleAccountDiscoInfo требует для PEP identity pubsub/pep и features
filtered-notifications, publish-options, publish, subscribe, create-nodes,
delete-items, delete-nodes, persistent-items, retrieve-items, auto-create.
Для modern PEP дополнительно проверяет item-ids/multi-items; для max-items
проверяет config-node-max. Push включается по urn:xmpp:push:0 на аккаунте.
Эти predicates воспроизведены в tests/push_discovery.py. Само приложение
в среде разработки не запускалось.

Стандарты:
- https://xmpp.org/extensions/xep-0163.html §6.1
- https://xmpp.org/extensions/xep-0357.html §4.1
- https://xmpp.org/extensions/xep-0379.html §3–5
- https://xmpp.org/extensions/xep-0401.html §3, §5.1

XEP-0379 определяет токен в presence и URI. Генерация серверной ссылки
использует контактную ad-hoc команду XEP-0401, не выдуманный IQ PARS.
Истёкший/неизвестный токен не даёт автоматических прав и сохраняет ручной
workflow. tests/preauth_network.py проверяет весь контактный flow через TLS.
