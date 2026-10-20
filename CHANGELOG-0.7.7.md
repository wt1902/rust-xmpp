# 0.7.7

- Встроенный http_altconnect: XRD/JRD host-meta discovery, CORS, HEAD/OPTIONS.
- Реклама включённых BOSH/WS, advertise_bosh/advertise_websocket и отключение
  discovery отдельно от транспорта.
- Custom http_paths.altconnect, HTTP Host/fallback и публичный URL reverse proxy.
- Публичные href из конфигурации с предпочтением HTTPS; native HTTP fallback.
- Конфликты с transport routes и неправильные advertise-типы отвергаются.

Включение и пример reverse proxy — docs/HTTP-ALTCONNECT.md.
