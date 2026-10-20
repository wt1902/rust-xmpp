# 0.7.0 — operational/authentication logging

Добавлен instance-owned logger с уровнями debug/info/warn/error, native-style
level maps, explicit sink ranges/sets, console/file, UTC millis, plain/JSON,
0600 append и сериализацией записей. SIGHUP переоткрывает ротируемые файлы,
сохраняя прежние дескрипторы при ошибке. Native syslog/произвольные plugin
sinks и полное hot reload не реализованы.

TCP/HTTP XMPP transports больше не теряют все ошибки без журнала. Единый ID
прослеживает TLS, SASL features/attempt/challenge, account lookup, точный класс
rejection, auth success, bind/resume и disconnect. Добавлены startup version,
SM hibernation/expiry, resource replacement, maintenance и основные входящие
S2S события. Секреты и XML переписки не передаются в logger; есть фильтр sensitive
keys и escaping. Подробная инструкция и таблица причин — docs/LOGGING.md.

Исправлены подтверждённые различия: PLAIN нормализует authentication identity
через SASLprep/nodeprep и использует canonical owner; authorization identity
проверяется после нормализации. SCRAM abort отвечает aborted, новая auth
может перезапустить обмен в пределах лимита попыток. Отказы proof и nonce
получили отдельные внутренние причины; wire authentication failure остаётся
обобщённым, чтобы не раскрывать внешнему клиенту состояние account store.

Новые сетевые регрессии проверяют 8 сценариев журналирования и SIGHUP,
20 случаев normalizing/retry в TLS1.2/1.3 и SASL1/2, плюс logger unit tests.
Оставшийся отказ конкретных Conversations/monocles на устройстве не воспроизведён;
для него теперь можно получить server-side reason и этап. Полная замена Prosody
не подтверждена, остальные ограничения перечислены в docs/COMPATIBILITY.md.
