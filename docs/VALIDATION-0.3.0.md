# Проверка 0.3.0

Проверено 2026-10-16, Linux x86_64, Rust 1.99.1
(`58cf8f9c3`, 2026-10-13). Использована чистая папка сборки, отключена
инкрементальная компиляция. Для тестовой сборки отключены debug symbols;
release собран с обычной оптимизацией Cargo. Исходники после проверки
больше не менялись.

| Проверка | Результат |
|---|---|
| `cargo test --locked` | 123 passed, 0 failed, 6 ignored |
| `cargo clippy --locked --all-targets -- -D warnings` | Успешно, без предупреждений |
| `cargo fmt --check` | Успешно |
| `cargo build --release --locked` | Успешно |
| Native storage/auth oracle | Успешно для SHA-1 и SHA-256, оба направления Rust ↔ настоящая Prosody |
| Native PEP oracle | Настоящие mod_pep/util.pubsub читают данные Rust, публикуют замену; Rust читает результат |
| Native MUC/MAM oracle | Настоящие mod_muc/mod_muc_mam восстанавливают комнату и affiliations, читают историю Rust, архивируют реальную native рассылку; Rust читает результат |
| Native CSI oracle | 15 решений о важности stanza совпадают с оригинальным mod_csi_simple |
| Большой архив, отдельный ignored test | Успешное потоковое чтение архива больше 128 MiB |
| `scripts/smoke.py` | TLS-сертификат, пароль и отказ неверному, независимый расчёт hash, bind, ping, сообщения, поддельный from, отказ входу без TLS |
| `scripts/integration_xmpp.py` | Roster/subscriptions, IQ routing, CSI/whitespace flush, MAM, блокировка, OMEMO PEP payload, MUC, offline, SM resume и корректное завершение по SIGTERM |
| `tests/sasl_network.py --spawn --hash sha1` | SASL1/SASL2, SCRAM, SSDP, подпись сервера, отказ неверному паролю |
| `tests/sasl_network.py --spawn --hash sha256` | То же для SHA-256; постоянный client_id, native push registration, max восстановления 259200 |
| `scripts/integration_http.py` | Реальные WSS и HTTPS BOSH, auth/bind, CSI, унаследованные namespace, roster/chat, upload IQ/PUT/GET и запрет повторного PUT |
| Federation TLS tests | Реальные взаимные TLS/CA/EXTERNAL, отказ подмене домена; 23 сообщения используют одно соединение, idle/EOF вызывают безопасное переподключение |
| `sh -n scripts/docker-entrypoint.sh` | Успешно |
| Docker image / Compose runtime | Не запускались: Docker в этой среде отсутствует |
| AF_UNIX admin socket test | Не запускался здесь: окружение запрещает Unix sockets. Протокол/команды отдельно проверены через in-memory duplex |

Таким образом, дополнительно к 123 обычным прошли **4 native oracle tests и
1 большой архивный тест**. Из шести отключённых по умолчанию тестов только
AF_UNIX остаётся непроверенным на настоящем сокете этой сборки.
Проверки формата не ограничены собственной копией парсера: oracle загружает
переданную оригинальную Prosody `cafd74b9c5ea`, её настоящий modulemanager,
storagemanager и скомпилированные native-библиотеки.

## Короткая нагрузочная проверка

`python3 scripts/load_smoke.py --clients 500`:

- 500 из 500 TLS-подключений авторизованы и получили разные ресурсы.
- 1500 ping: median 12.512 ms, p95 15.492 ms, max 19.709 ms.
- 500 из 500 направленных сообщений доставлены; ошибок нет.
- Создание подключений: 0.604 s при параллелизме 50.
- FD: 10 до нагрузки, 510 с подключениями, 10 после отключения.
- Измеренный peak RSS 24352 KiB; CPU процесса после нагрузки 1.3 s.

Это один аккаунт с 500 ресурсами на loopback, TLS+PLAIN, короткий прогон.
Это не тест 500 независимых пользователей, не нагрузка полного набора модулей,
не долговременный benchmark и не доказательство отсутствия утечек памяти.
Память allocator после отключения оставалась выделенной. Сырые измерения
доступны в `validation-results.json`.

## Что ещё не доказано

Нет проверки настоящими Monal/Conversations/Gajim, внешним push-шлюзом,
разнообразными публичными XMPP-серверами и полной копией рабочих данных.
Не проверены upload 10 GiB, длительная нагрузка, Docker UID/GID/TLS и откат
вашей рабочей установки. Это необходимые проверки перед утверждением
«полная замена без изменений». Функциональные отличия перечислены в
`COMPATIBILITY.md`.

Для повторения обычных проверок — команды из README. Для native oracle —
`scripts/prosody_compat/verify.sh`; для AF_UNIX на целевом Linux:

```bash
cargo test --locked --test admin_socket -- --ignored
```
