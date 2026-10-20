# http_altconnect (0.7.7)

Встроенный модуль публикует альтернативные XMPP connection methods:

- GET `/.well-known/host-meta`: XRD, Content-Type application/xrd+xml.
- GET `/.well-known/host-meta.json`: JRD, Content-Type application/json.

Оба ответа содержат Access-Control-Allow-Origin: *. HEAD возвращает те же
заголовки без тела; OPTIONS разрешён; остальные методы дают405. Неизвестные
пути и неразрешённый HTTP Host не обслуживаются. Query не изменяет формат
и не включает JSONP. В логах запрос классифицируется как altconnect.

Реализация сверена с supplied plugins/mod_http_altconnect.lua cafd74b9c5ea.
Источник протокола: https://xmpp.org/extensions/xep-0156.html.

## Включение

Добавьте `http_altconnect` в существующий modules_enabled, сохранив остальные
модули. В Lua, например:

```lua
modules_enabled = {
    -- остальные существующие модули
    "websocket";
    "bosh";
    "http_altconnect";
}
advertise_bosh = true;
advertise_websocket = true;
```

Это фрагмент: не заменяйте им весь рабочий список modules_enabled.
Оба advertise-параметра по умолчанию true; false скрывает соответствующий Link.
Выключенный/неподключённый транспорт не рекламируется. Если нет ни одного
транспорта, XRD пустой, JSON содержит links: []. Отключение http_altconnect
убирает discovery endpoints, сохраняя работу WS/BOSH.

Адреса учитывают http_host, http_paths.bosh/websocket и http_external_url.
При отсутствии внешнего URL выбирается первый настроенный HTTPS listener,
затем первый HTTP listener; значения не зависят от Host/Forwarded в запросе.
Пустой interfaces список не считается действующим listener.

Пример для HTTPS proxy с удаляемым публичным префиксом /xmpp/:

```lua
http_external_url = "https://wthome.ru/xmpp/";
http_paths = {
    websocket = "/ws";
    bosh = "/bind";
}
```

Опубликованные href: https://wthome.ru/xmpp/bind и wss://wthome.ru/xmpp/ws.
http_external_url меняет публичные адреса, внутренние пути остаются /bind и /ws.
`http_paths.altconnect` меняет внутреннюю базу discovery, например `/discover`:
в этом случае endpoint — `/discover/host-meta[.json]`. `$host` поддерживается.
Путь transport, конфликтующий с активным host-meta endpoint, отвергается при
check-config/startup вместо неоднозначной маршрутизации.

## Публичный discovery

Клиент запрашивает well-known на HTTPS origin XMPP-домена, например
https://wthome.ru/.well-known/host-meta. HTTPS listener5281 сам по себе не
создаёт публикацию на443: используйте существующий reverse proxy или port mapping.
Пример дополнительных location внутри TLS server Nginx, если backendHTTP5280:

```nginx
location = /.well-known/host-meta {
    proxy_pass http://127.0.0.1:5280;
    proxy_set_header Host wthome.ru;
}
location = /.well-known/host-meta.json {
    proxy_pass http://127.0.0.1:5280;
    proxy_set_header Host wthome.ru;
}
```

Эти location публикуют discovery без transport-префикса /xmpp/; соответствующие
WS/BOSH location по-прежнему настраиваются согласно HTTP-PROXY.md.
При custom altconnect mount proxy должен переписать well-known на него.

XEP-0156 требует HTTPS загрузку metadata и только https/wss href. Для native
совместимости supplied module HTTP/WS fallback также сохранён: если настроен
только HTTP, ссылки будут http/ws. Для стандартного защищённого discovery
настройте HTTPS listener или HTTPS http_external_url. Автоматическое изменение
production DNS, proxy или TLS-сертификатов не выполняется.

Проверка с действительным CA (для self-signed добавьте --cacert cert.pem):

```bash
curl -i https://wthome.ru/.well-known/host-meta
curl -i https://wthome.ru/.well-known/host-meta.json
```

Модуль включается на единственном runtime VirtualHost. Host Meta2/XEP-0487,
DNS TXT/SRV changes, redirects на чужие Host и автоматический запуск браузера
не являются частью этого плагина. Результаты локальных проверок — VALIDATION.md.
