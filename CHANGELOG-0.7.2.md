# 0.7.2 — PEP operations and diagnostics

Предоставленный INFO-журнал версии0.7.1 подтверждает успешный SCRAM login и
resource bind Conversations/monocles. Он не содержит PubSub IQ: конкретный
production отказ PEP из него определить нельзя. Диагноз «данные OMEMO повреждены»
по такому журналу не устанавливается.

Исправлены найденные при проверке совместимости дефекты:

- IQ error теперь возвращает from исходного to и исходный payload, как требуется
  для ответа от имени bare-аккаунта. Отсутствующие PEP узел/элемент по-прежнему
  возвращают item-not-found, что OMEMO-клиент обрабатывает как повод публикации.
- Эффективные notification defaults материализуются при обработке существующих
  узлов, включая ранее сохранённые конфигурации с пропущенными полями.
  Publish-options больше не сообщает ложный precondition-not-met для опций,
  которые доставка уже считала включёнными. Реальное несовпадение по-прежнему
  возвращает conflict/precondition-not-met; чужое изменение узла запрещено.
- INFO событие pubsub-iq-result показывает action, node_kind, status, condition,
  precondition_not_met, количество запланированных deliveries; disco дополнительно
  показывает pep_identity, persistent_items, publish_options. Никаких payload,
  node suffix, device/item/IQ IDs или ключевых данных. deliveries не является
  подтверждением получения телефоном. iq-dispatch-failed сообщает безопасный
  io_kind для ошибок хранения/модулей, не печатая их исходный текст.

Добавлены сценарии первого OMEMO запуска, no-to публикации avatar/devices/bundle,
owner config recovery, TLS/restart persistence, native-like omitted defaults,
filtered caps events и проверка redaction. Это проверки wire/storage, не запуск
Android приложений или криптографическая проверка тестовых bundle bytes.

DNSSEC: публичные DS/DNSKEY wthome.ru на дату проверки отсутствуют. Инструкция
подписания DNS-зоны и DS у регистратора — docs/DNSSEC.md. Это отдельная задача
оператора DNS, не capability XMPP и не исправление в этой сборке.
Полная замена Prosody пока не подтверждена: docs/COMPATIBILITY.md.

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
