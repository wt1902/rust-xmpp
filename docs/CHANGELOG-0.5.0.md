# 0.5.0

Исправлены клиентские проверки PEP и push:

- Account disco на bare JID: identity account/registered, pubsub/pep при PEP,
  automatic/filtered PubSub features. Серверный адрес остаётся server/im.
- Push feature urn:xmpp:push:0 появляется на своём аккаунте с cloud_notify,
  независимо от PEP. Не объявляется identity внешнего push-шлюза pubsub/push.
- При раннем PEP reply сохраняются MAM и остальные account features, включая
  поддерживаемые bookmarks/vCard conversions; leaf disco/ACL не подменяются.
- Регрессия воспроизводит predicates handleAccountDiscoInfo из исходника Monal.
- XEP-0379: preauth сохраняется в пересылке и pending presence для неизвестного
  серверу токена; валидный серверный token однократный, с expiry/owner scope,
  приводит к подтверждению и обратному запросу подписки.
- XEP-0401: реализована контактная ad-hoc команда urn:xmpp:invite#invite и её
  discovery на серверном JID; выдаётся URI и expiry. Нет прав регистрации,
  нет ibr=y, landing page и account-creation command.
- RFC6121 preapproval объявляется в stream features вместе с roster versioning.
- Unscoped invite_token совместим с настоящим mod_invites; native test
  проверяет создание/использование токенов в обе стороны и изоляцию scope.

Текущий конфиг с roster, pep, cloud_notify не требует редактирования для этих
исправлений. Клиенту нужно повторить discovery после переподключения аккаунта.
Доставка push на физическое устройство зависит от используемого шлюза;
проверена серверная регистрация и сериализация, а не реальный APNs/FCM цикл.
Функциональные пределы полной замены остаются в COMPATIBILITY.md.
