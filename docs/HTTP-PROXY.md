# HTTP-пути и reverse proxy

С0.7.5 WS/BOSH используют настройки `http_paths.websocket` и `http_paths.bosh`.
`http_paths.file_share` задаёт внутренний путь upload-компонента. Настройки
VirtualHost/Component имеют приоритет над глобальными; `$host` заменяется именем
XMPP-хоста. Дефолты: `/xmpp-websocket`, `/http-bind`, `/file_share`.
HTTP-пути задаются без query/fragment; конечный `/` допускается. Поддержаны
литеральные RFC3986 path-символы и percent encoding, например `/v1:ws` и
`/bind%20endpoint`. Закодированные slash/backslash, control и dot segments
отвергаются, чтобы избежать неоднозначного переписывания прокси.

`http_host` задаёт HTTP Host, который proxy должен отправлять backend.
`http_default_host` глобально выбирает fallback для неизвестного HTTP Host.
Runtime по-прежнему обслуживает один VirtualHost и его компоненты.

`http_external_url` задаёт публичный HTTP(S) origin и необязательный префикс.
Например, `https://chat.example.org/xmpp/` вместе с `http_paths.bosh: /bind`
соответствует публичному `https://chat.example.org/xmpp/bind` и внутреннему `/bind`.
Прокси должен удалить `/xmpp/` перед отправкой backend. Эта настройка сама по
себе не меняет внутренние маршруты и не включает автоматическое discovery.
Для WebSocket клиент использует эквивалентный `wss://` URL.

## TLS на прокси

Пример фрагмента YAML для существующего конфига (сохраните остальные параметры):

```yaml
global:
  http_ports: [5280]
  http_interfaces: [127.0.0.1]
  trusted_proxies: [127.0.0.1, '::1']
  http_legacy_x_forwarded: true
  http_default_host: wthome.ru
  http_external_url: https://wthome.ru/xmpp/
  http_paths:
    websocket: /ws
    bosh: /bind
  http_cors_override:
    websocket:
      origins: [https://conversejs.wthome.ru]
    bosh:
      origins: [https://conversejs.wthome.ru]
```

Nginx: переменная map задаётся внутри `http`, location — внутри TLS server.

```nginx
map $http_upgrade $xmpp_connection {
    default upgrade;
    '' close;
}

location /xmpp/ {
    proxy_pass http://127.0.0.1:5280/;
    proxy_http_version 1.1;
    proxy_set_header Host wthome.ru;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $xmpp_connection;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_read_timeout 120s;
}
```

Публичные адреса: `wss://wthome.ru/xmpp/ws` и
`https://wthome.ru/xmpp/bind`. Для прежнего прямого WSS5281 настройка
прокси не требуется. Origin — адрес страницы Converse, а не WSS endpoint.

IP/CIDR в `trusted_proxies` разрешают доверять forwarded-данным только от
указанных socket peers. По умолчанию доверены loopback127.0.0.1 и::1.
Пустой список отключает доверие. Не задавайте `0.0.0.0/0` для публичного backend.
X-Forwarded-For разбирается справа налево до первого недоверенного адреса.
X-Forwarded-Proto=https разрешает HTTP WS/BOSH без consider_*_secure только
для доверенного прокси. Прямой HTTP без такого подтверждения получает403,
если `consider_websocket_secure`/`consider_bosh_secure` не включены явно.
Не включайте consider_*_secure на открытом внешнем HTTP listener.

При `http_legacy_x_forwarded: false` используются RFC7239 `Forwarded`
с IP, bracketed IPv6/port, `proto=https` и цепочками доверенных прокси.
В RFC-режиме защищённость TLS termination принимается от ближайшего доверенного
прокси; каждый следующий разобранный hop также должен иметь `proto=https`. Это
намеренно отличается от консервативного `secure AND proto` supplied native
revision, не позволявшего так отметить HTTP backend защищённым.
`X-Forwarded-Host`/`Forwarded host` не заменяют HTTP Host: настройте Host на прокси.

Поддержаны HTTP reverse proxies, сохраняющие WebSocket Upgrade и BOSH body.
HAProxy PROXYv1/v2, произвольные Lua HTTP-приложения и горячая перенастройка
маршрутов не реализованы. Nginx-конфигурация дана для оператора; настоящий
Nginx и production-сертификат в локальном прогоне не запускались.

Основание семантики: https://prosody.im/doc/http и supplied mod_http.lua.
