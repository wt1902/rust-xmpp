# PEP «повреждено»: проверка 0.7.4

В предоставленном журнале0.7.1 monocles и Conversations успешно авторизовались.
Содержимого PubSub запросов/ответов в INFO-журнале не было. Поэтому изменения
0.7.2 устраняют воспроизведённые ошибки совместимости и добавляют нужные данные
для следующей диагностики, но не доказывают причину именно вашего индикатора.

## Предикаты клиента

В проверенном monocles AccountActivity ветка PEP broken использует
AxolotlService.isPepBroken(), а не только bare-account disco. Флаг устанавливается
при ответе с ошибкой, отличной от item-not-found, на чтение own bundle, при
ошибках публикации device list, кроме ожидаемого precondition-not-met, и при
повторяющихся пустых device list. Отсутствие узла при первом запуске нормально:
сервер должен ответить item-not-found, затем принять публикацию. Источник master
может отличаться от версии установленного приложения.

## После обновления

1. Пересобрать и перезапустить сервер. События starting/ready должны показывать
   0.7.4. Выполнить переподключение клиента; если статус сохраняется только в
   текущем процессе приложения, полностью закрыть и снова открыть приложение.
   Удалять аккаунт, локальные ключи, device list или серверное хранилище не нужно.
2. Включить существующий INFO sink (JSON или plain), воспроизвести открытие
   настроек аккаунта/обновление аватара/публикацию OMEMO.
3. Проверять pubsub-iq-result для того же connection. node_kind различает
   omemo-bundle, omemo-devices, avatar-data, avatar-metadata, bookmarks, custom;
   неизвестное имя не записывается. status=result означает успешный ответ на IQ.
4. items/item-not-found до первой публикации ожидаем. conflict +
   precondition_not_met=true допускает owner configure GET/SET и повтор publish.
   forbidden, feature-not-implemented или internal-server-error на собственном
   узле требует разбора; iq-dispatch-failed io_kind=PermissionDenied указывает
   на ошибку доступа к данным. io_kind=none означает не-I/O ошибку; её текст
   намеренно не печатается, чтобы не раскрыть содержимое данных.

Событие формируется для IQ, прошедших локальный dispatch. Ранние ветки
блокировки/удалённой маршрутизации могут его не формировать; отсутствие события
само по себе не доказывает, что клиент не отправил запрос.

Disco flags подтверждают рекламу features, но не доступность каждого узла.
deliveries — количество созданных маршрутизаций, не доставки/ACK. Чтение и
публикация PEP не требуют согласия на раскрытие XML или OMEMO данных в журнале:
диагностические поля ограничены известными значениями протокола.

Автоматические проверки: tests/pep_client_interop.rs, tests/pep_client_network.py,
tests/pep_discovery.rs, tests/pubsub_persistence.rs, tests/iq_errors.rs. Network
fixtures используют синтетические ключевые bytes, не настоящие приватные ключи.
Полная миграция реальных данных и поведение Android приложения пока не проверены.

Источники: https://codeberg.org/monocles/monocles_chat —
src/main/java/eu/siacs/conversations/ui/AccountActivity.java,
crypto/axolotl/AxolotlService.java, generator/IqGenerator.java,
xmpp/pep/PublishOptions.java; https://xmpp.org/extensions/xep-0060.html;
https://xmpp.org/rfcs/rfc6120.html. Master mutable; дата проверки 2026-10-20.

Проверка мигрированных форм выявила и исправила несовместимость0.7.1:
notification_type, itemreply и native payload_type выдавались в форме, но
не принимались parser при повторной отправке. Теперь payload_type соответствует
wire pubsub#type; notification_type normal/headline и itemreply
none/owner/publisher валидируются. Как в native PEP, уведомления PEP сохраняют
headline; standalone PubSub учитывает normal/headline. itemreply=publisher
включает bare publisher в чтение и уведомления, none/owner не раскрывают его
(поведение предоставленного native handler). Поддержаны publish_model
open/subscribers с проверками блокировок/outcast, без изменения owner-only
прав на create/configure/retract. Неизвестные enum значения отвергаются.
Baseline regression на исходниках ZIP0.7.1 воспроизводит rejected whole-form
submission и ложные default preconditions; патч проходит эти сценарии.

Старый Rust config.type нормализуется в native payload_type при обработке
узла; это предотвращает дублирование pubsub#type при смешанной миграции.

## Успешный IQ, но старый первый item

Исправлен порядок выдачи: новые элементы теперь первые, как в supplied native
Prosody. Старые0.7.2 ответы на multi-item node могли содержать пустой old item
перед populated current item. IqParser.getItem monocles выбирает первый item.
Это отдельный дефект от malformed/error ответов; type=result недостаточно
для доказательства корректного состояния, видимого клиенту.

С0.7.3 для self-account/implicit items проверяйте items_count,
first_content_kind=omemo-devices и first_device_count. Если счётчик устройств0,
первый список структурно пуст; если items_count>1, узел хранит несколько записей.
Сам по себе пустой список допустим и не означает поломку OMEMO. Другие аккаунты
могут законно отвечать forbidden из-за ACL. Диагностические поля не раскрывают
ID, XML или ключевые данные. Для подтверждения прежней production причины
нужна структура реальных данных; в текущем журнале0.7.2 этих счётчиков нет.

Regression: tests/pep_item_order.rs и tests/pep_order_network.py. Дополнительный
ignored oracle запускает настоящий mod_pep и подтверждает порядок current,old.
Источник parser: monocles IqParser.java getItem180-190/deviceIds193-228
(проверенный mutable master); native source: plugins/mod_pubsub/pubsub.lib.lua
archive_itemstore:items reverse=true, util/pubsub.lua service:get_items.

## Что установлено по production0.7.3

Own-account PEP discovery успешен; own devices replies имеют1 item и
непустые XML списки1/2/6. Исправление порядка нескольких items не объясняет
этот случай. Элементы device ещё не означают успешно разобранные Android ID.
Теперь valid_device_count считает уникальные signed32 ID по inspected Java
Integer.valueOf (без whitespace trimming), invalid_device_count — пропущенные/
некорректные/выходящие за диапазон. device_protocol различает legacy/omemo2/other.
Это client-parser diagnostics, не полная валидность XEP0384 или криптографии.

notification-generated показывает структуру локально сгенерированного события,
items_count, content_present, device_protocol и счётчики. Событие пишется ДО routing,
без transport connection ID и без адресата: оно не доказывает получение клиентом.
Не все remote delivery ветки проходят через этот logger. Payload suppression
include_payload=false может давать пустой item event при непустом IQ; тест покрывает
этот случай. Флаг false здесь не доказывает, что именно ваш узел настроен так.

Для определения ветки клиентской ошибки используйте отфильтрованный клиентский
журнал, а не полный XML/ключи. При доступном adb:

```sh
adb logcat -v brief | python3 scripts/filter-android-pep-log.py
```

Для сохранённого клиентского журнала:

```sh
python3 scripts/filter-android-pep-log.py < client.log
```

Выход содержит только фиксированные причины: empty-device-list-retry-limit,
device-list-publish-error, bundle-read-error, bundle-publish-error,
empty-device-list-publish. Строки без этих известных фраз не выводятся. Версия
клиента может использовать другие сообщения; отсутствие вывода не доказывает
отсутствие проблемы. Пароли/JID/ID/произвольный текст/XML не копируются в выход.
Нужны одна такая причина и соответствующие notification-generated/own-account
IQ события для дальнейшего конкретного исправления. Текущий источник master
не гарантирует совпадение с установленной версией приложения.
