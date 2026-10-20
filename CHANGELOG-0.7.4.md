# 0.7.4 — Converse Origin, HTTP interfaces and PEP diagnostics

Пользователь подтвердил страницу Converse https://conversejs.wthome.ru/.
Исходный http_cors_override.websocket.origins разрешал только
https://wthome.ru. В изолированном TLS тесте исходная политика даёт101 для
wthome.ru и403 для реального Origin Converse; после добавления точного Origin
Converse получает101. examples/config.json и отдельный YAML fragment обновлены.
Рабочий конфиг на целевом сервере нужно изменить отдельно от сборки.
Wildcard разрешение Origin не добавляется; проверка TLS сохраняется.

Исправлено игнорирование http_interfaces/https_interfaces: раньше HTTP всегда
слушал0.0.0.0. Теперь учитывается настройка соответствующего протокола, fallback
к interfaces; * раскрывается в IPv4/IPv6, дубликаты убираются, IPv6 socket V6ONLY.
Тест HTTPS-only с глобальным interfaces127.0.0.1 и отдельным HTTPS ::1 подтверждает
обе привязки. INFO listener-ready показывает address/transport/route flags.

Добавлена диагностика HTTP с connection ID: TLS установление/отказ/таймаут,
фиксированный класс websocket/bosh/other, HTTP status, завершение. Ни URI,
query, Origin/header values, bodies, пароли или raw errors не печатаются.
Новый serve_router_logged сохраняет прежний serve_router API без logger.

Новый RFC7395 тест выявил настоящий дефект закрытия до SASL: stream close
разбирался как XML document и считался invalid-xml. Теперь закрытие отвечает
stream close, штатно завершает authenticate, затем закрывает WebSocket.
Проверены оба WS пути и browser token-list headers/subprotocol xmpp.

PEP: production0.7.3 own IQ replies содержат1 item и непустые списки1/2/6 устройств,
так что прошлый multi-item порядок не объясняет текущий случай. Нет доказанного
нового отказа сервера PEP и нет обещания исправления индикатора этим патчем.
Добавлены legacy/OMEMO2 distinction, valid_device_count/invalid_device_count
по inspected Android signed32 parsing и notification-generated content_present.
Синтетический TLS тест показывает: include_payload=false даёт пустое уведомление,
при этом IQ retrieval по-прежнему содержит устройства. Это проверка диагностики,
а не установленная production конфигурация. ID/XML/ключи в журнал не выводятся.

scripts/filter-android-pep-log.py печатает только фиксированные причины из
клиентского журнала и помогает определить фактическую ветку pepBroken.
DNSSEC повторно: DS/DNSKEY без Answer, AD=false; изменение DNS не выполнялось.
Полная замена Prosody всё ещё не подтверждена, см. COMPATIBILITY.md.
