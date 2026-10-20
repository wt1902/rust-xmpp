#0.7.5

- Настраиваемые HTTP-пути WS/BOSH/upload, HTTP Host/fallback и публичный URL
  reverse proxy с префиксом.
- Доверенные proxy IP/CIDR, обработка X-Forwarded-For/Proto или RFC7239
  Forwarded, безопасное игнорирование заголовков недоверенного peer.
- Проверка защищённости WS/BOSH на запросе, TLS termination без глобального
  consider_*_secure; эффективный peer в серверной диагностике.
- Проверки кастомных маршрутов и loopback TLS reverse proxy; инструкция
  docs/HTTP-PROXY.md.

Полная замена Prosody ещё не подтверждена; актуальные границы —
docs/COMPATIBILITY.md, результаты — docs/VALIDATION.md.
