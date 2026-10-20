# 0.7.8

- Несколько XEP-0363 `http_file_share` components на общих HTTP listeners:
  маршрутизация по Host и mount, отдельные discovery/IQ slots, квоты и tokens.
- Разные HTTP hosts могут использовать одинаковые mounts; один host — разные
  непересекающиеся paths. Неоднозначные одинаковые/вложенные mounts отвергаются
  при startup с именами components и конфликтующими путями.
- Upload dispatcher компонуется с WebSocket, BOSH и `http_altconnect` без
  объединения конфликтующих fallback routers.
- Сохранён local backend; добавлен S3-compatible gateway с SigV4, path-style
  addressing, HTTPS и loopback HTTP для изолированных тестов. Credentials
  можно получать через поля `*_env`.
- Multipart передача частями 8 MiB, максимум восемь активных S3 uploads
  на component,
  проверка stream size, single-use PUT, abort при ошибке/отмене и recovery
  сохранённых multipart records перед открытием listeners.
- Native XMPP metadata остаются локальными; backend identity guard запрещает
  скрытую смену хранилища при существующих slots. Rotation S3 credentials
  не меняет identity backend.
- Добавлены network regressions для нескольких components и независимый
  локальный S3 protocol fixture с повторной проверкой SigV4. Fixture не
  подтверждает совместимость с production AWS S3 или MinIO.

Настройка, lifecycle `AbortIncompleteMultipartUpload`, recovery и ограничения:
[docs/HTTP-UPLOAD.md](docs/HTTP-UPLOAD.md).

Реальная передача 10 GiB по HTTPS с local backend проверена: полный PUT/GET,
совпадение SHA-256, Range за 4 GiB и выборочное измерение памяти. Полная
регрессия, нагрузка 500 TLS клиентов и native reference tests пройдены.
Результаты: [docs/VALIDATION-0.7.8.md](docs/VALIDATION-0.7.8.md).
