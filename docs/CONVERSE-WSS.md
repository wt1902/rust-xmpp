# Converse.js: https://conversejs.wthome.ru → WSS5281

Страница браузера и endpoint имеют разные роли:

- Страница: https://conversejs.wthome.ru/ → Origin https://conversejs.wthome.ru.
- XMPP endpoint: wss://wthome.ru:5281/xmpp-websocket.

В рабочий YAML конфиг под global добавьте точный Origin, сохранив остальные
настройки http_cors_override и текущие origins:

```yaml
global:
  http_cors_override:
    websocket:
      enabled: true
      origins:
        - https://wthome.ru
        - https://conversejs.wthome.ru
```

Это fragment, не полный конфиг: не заменяйте им hosts/data_path/SSL и прочие
параметры. examples/converse-origin.fragment.yaml содержит тот же фрагмент;
полный examples/config.json тоже обновлён. Примените изменение к вашему
prosody.rust-xmpp.cfg.yaml и перезапустите процесс после пересборки0.7.4.
Endpoint можно оставить прежним. В настройке клиента websocket_url должен
указывать полный WSS URL с путём. Сертификат endpoint должен быть доверенным
и действительным для wthome.ru; Origins не меняют TLS hostname validation.

Изолированный test воспроизводит исходный403 для нужного Origin и исправленный101.
Он использует настоящую проверку тестового CA/hostname, оба endpoint paths,
HTTP/1.1 Connection token list, обязательный subprotocol xmpp, отсутствие/неверный
subprotocol400, посторонние origins403, неизвестный путь404, invalid CA rejection,
RFC7395 open/features/close до SASL. Параметры auth/bind отдельно проверяются
sasl_web_network и integration_http. Интерфейсы127.0.0.1 и::1 подтверждены по TLS.

## Как читать новый журнал

- http listener-ready address=[::]:5281/0.0.0.0:5281, transport=https и
  websocket=enabled — настроенная доступность listener/route.
- http request-complete route=websocket status=403 — запрос отклонён политикой.
  Сопоставляйте Origin именно страницы с конфигом. В журнале значение Origin
  скрыто, чтобы не писать произвольные заголовки.
- status=101 — выполнен Upgrade; дальнейшие auth/bind события идут в c2s.
- 400 — отсутствующий/неверный xmpp subprotocol или некорректный Upgrade.
- 404 — endpoint не найден; phase=tls-handshake указывает на TLS этап.

Журнал не доказывает browser connectivity через ваш firewall/proxy/DNS.
Попытка read-only проверки production endpoint в среде разработки не смогла
разрешить имя, поэтому живой wss://wthome.ru:5281 здесь не проверен.
Origin не расширяется до wildcard и TLS не отключается.
