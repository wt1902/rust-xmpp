# Проверка 0.7.2

Проверено 2026-10-20, Linux x86_64, Rust 1.99.1.
Полный лог: validation-logs-0.7.2/verify.txt; машинный отчёт: validation-results.json.

| Проверка | Результат |
|---|---|
| cargo test --locked | 206 passed, 0 failed, 9 ignored |
| fmt, Clippy all-targets -D warnings, release build | Успешно |
| Baseline0.7.1 | Из исходников предыдущего ZIP воспроизведены неверное IQ error addressing, ложный конфликт notification defaults, отказ native whole-form config submit |
| PEP unit | 7 сценариев: first own missing bundle, no-to publish/read/caps, implicit defaults, native config roundtrip + stale type canonicalization, notification style, publisher visibility, open/subscriber models + outcast/blocklist |
| PEP STARTTLS | Fresh + migrated metadata, legacy/OMEMO2 item selectors, no-to publish, native form GET/SET/retry, restart persistence, owner restriction, INFO JSON protocol-only diagnostics |
| Предыдущие сети | TLS/PLUS/SSDP/Android SASL1/2, retry/normalization, logging/rotation, Bind2/resume, disco/push, IBR/seclabels, preauth, resource rebinding, HTTP/HTTPS BOSH/WSS/upload — успешно |
| Native Prosody | 6 module/storage tests + 1 двусторонняя STARTTLS/SASL EXTERNAL федерация — успешно |
| Нагрузка | 100 аккаунтов, 500 TLS-соединений, 5000 ping, 5000 сообщений, 10000 MAM записей; failures=[] |
| Публичный DNS | У wthome.ru не обнаружены DS/DNSKEY, AD=false. Google/Cloudflare read-only; production не менялся |

Запуск: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh; native checks требуют
PROSODY_REFERENCE_SOURCE и PROSODY_REFERENCE_LUA, см. scripts/prosody_compat/README.md.
Весь итоговый прогон сделан после изменений исходников; последующие изменения
касаются только отчётов и упаковки.

Первый baseline roundtrip проверяет ошибку wire name payload_type; повторный
baseline убирает только ранние assert имени поля, чтобы независимо показать
feature-not-implemented на whole-form SET. Остальные baseline тесты не менялись.
Лог содержит намеренно упавшие regression tests на0.7.1, а не ошибки0.7.2.

Предоставленный INFO0.7.1 журнал не содержит конкретных отказавших PubSub IQ;
причина именно пользовательского Android индикатора пока не доказана. Реальные
приложения не запускались; тестовые bundle bytes синтетические. Shared OMEMO2
multi-item test явно запрашивает max_items=max: это не утверждение, что клиент,
запрашивающий только open access, автоматически хранит все устройства при
native default max_items=1. Native-like metadata fixtures не заменяют полную
миграцию production. Крупный архив последний раз проверен0.5.0; AF_UNIX admin
нуждается в разрешённом хосте. Полная замена Prosody, APNs/FCM, целевое окружение
Docker/UID/TLS и длительная эксплуатация пока не подтверждены.
