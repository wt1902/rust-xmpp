# Проверка 0.6.1

Проверено 2026-10-20, Linux x86_64, Rust 1.99.1.
Полный лог: validation-logs-0.6.1/verify.txt.
Машинный отчёт: validation-results.json. Предыдущие отчёты сохранены отдельно.

| Проверка | Результат |
|---|---|
| cargo test --locked | 178 passed, 0 failed, 9 ignored |
| Clippy all-targets -D warnings; fmt; release build | Успешно |
| Android SASL | 32 сочетания TLS1.2/1.3 × SHA1/256 × SASL1/2 × SSDP on/off × valid/invalid binding |
| Настоящий TLS exporter/endpoint | 14 обменов: SASL1/2, exporter TLS1.3, endpoint TLS1.2/1.3, full SSDP lists, server signature, tampered binding и отключённый PLUS |
| WSS SCRAM | SASL1/2 с y,,, отсутствие CB/PLUS, правильный SSDP без пустого CB separator, server signature, bind и ping |
| Certificate digest | 4 теста с OpenSSL fixtures: weak-hash upgrade, SHA2, RSA-PSS, ECDSA, malformed/unsupported DER |
| Старый 0.6.0 | 4 Android TLS1.2 отказа воспроизведены; WSS SSDP mismatch воспроизведён отдельно |
| Остальная сеть | TCP modules, offline/SM, SIGTERM, SCRAM, Bind2, inline resume, PEP/push discovery, preauth, resource policies, HTTPS BOSH/WSS и upload — успешно |
| Native Prosody | 6 module/storage ignored tests + 1 двусторонний TLS EXTERNAL federation test — успешно |
| Нагрузка с MAM | 100 аккаунтов, 500 TLS-соединений, 5000 ping, 5000 сообщений, 10000 архивных записей; failures=[] |

Запуск: XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh.
Native проверки требуют PROSODY_REFERENCE_SOURCE и PROSODY_REFERENCE_LUA;
инструкции в scripts/prosody_compat/README.md. Большой архив проверен в 0.5.0
и сейчас не повторялся; AF_UNIX admin требует разрешений целевого хоста.

Android selector в Python повторяет исследованный путь Conversations, а не
всё приложение. TLS1.3 exporter проверяется настоящим Rust/rustls клиентом;
Python на TLS1.3 использует endpoint binding, поскольку stdlib не даёт exporter.
У current monocles есть дополнительный fallback; детали в ANDROID-SASL.md.

Реальные Monal/Conversations/monocles на устройствах, APNs/FCM, production data,
Docker/UID/TLS целевого хоста и длительная эксплуатация не проверены. Остаточные
различия — COMPATIBILITY.md. Полная замена Prosody пока не подтверждена.
