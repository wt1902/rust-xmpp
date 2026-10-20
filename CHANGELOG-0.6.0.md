# 0.6.0 — переподключение и восстановление сессий

Исправлена причина bind conflict при повторном входе с тем же resource:
раньше runtime всегда отклонял новый bind, включая ресурс hibernating SM.
Теперь используется native `conflict_resolve`: default/kick_old заменяет
старый ресурс, kick_new возвращает conflict, increment выбирает свободный
суффикс #N, random — независимый UUID. Ответ содержит фактически выданный JID.
Одинаковая политика применяется к обычному bind и Bind2.

Старый transport получает stream conflict/close; его cleanup не удаляет новый
ресурс. Замена отзывает прежний resume token. Очередь и счётчики SM переносятся
только при успешном resume, а не при новой привязке ресурса.

SM resume допускает ещё живое старое TCP-соединение, проверяет владельца,
токен и h до takeover. Восстановленное состояние получает отдельный Arc:
старый обработчик не может изменять его acknowledgements, очередь и CSI.

Добавлен SASL2 inline SM resume. Resumed помещается в success с полным JID,
затем повторяются неподтверждённые stanzas. Успешный resume подавляет Bind2;
при неуспехе остаётся Bind2/обычный bind fallback. SM рекламируется в SASL2
inline только при включённом smacks.

Исправлены teardown-гонки BOSH terminate и WebSocket close: транспорт даёт
engine завершить cleanup перед fallback abort. Внезапный сетевой обрыв
остаётся негрейсфул, сохраняя возможность SM resume.

Регрессии: tests/resource_sessions.rs, tests/resource_rebind.py,
tests/sasl2_resume.py, tests/http_transport.rs и scripts/integration_http.py.
Все сетевые fixtures используют отдельные конфиги и временные данные.

Не выполнена проверка на настоящем устройстве Monal/Conversations, рабочих
данных и APNs/FCM. Флаг --experimental и пределы docs/COMPATIBILITY.md остаются.
