# 0.8.2 — задержки личных сообщений

- Личные сообщения и SM ACK больше не ждут сетевую отправку push. Уведомления
  отправляются через очередь1024 с максимум8параллельных маршрутов; worker
  и его задачи отменяются при завершении serve. Ошибки очереди/маршрута логируются.
- Offline сообщение сохраняется до публикации push, чтобы проснувшийся клиент
  мог сразу получить его. Подтверждена очередь при первом TLS stream push gateway.
- По умолчанию CSI считает важными bodyless OMEMO legacy/2, delivery receipts
  и chat markers. Явный список `csi_important_payloads` заменяет расширенные defaults.
  Низкоприоритетный headline по-прежнему буферизуется. Policy обновляется и при SM resume.
- Выбор адресатов и carbons фильтрует владельцев до захвата session mutex;
  зависшая сессия чужого аккаунта не задерживает этот путь. Duplicate SM ACK
  без изменения durable counters/queue не переписывает snapshot.
- Bind2 и MAM metadata IQ читают только первый/последний native record вместо
  сканирования всей истории. Индекс не требуется; recovery/лимиты записи сохранены.
- Добавлен `message-processing-slow`: обработка message дольше250мс, поля
  duration_ms/route, без payload/токенов. Это время обработки сервером, не peer receipt.
- Новые сетевые регрессии включены в verify-local.sh/GitHub CI.

Причины, изменение CSI policy, измерения и ограничения:
[docs/PERSONAL-MESSAGE-LATENCY.md](docs/PERSONAL-MESSAGE-LATENCY.md).
