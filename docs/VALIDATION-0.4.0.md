# Проверка 0.4.0

Проверено 2026-10-20 в Linux x86_64, Rust 1.99.1. После всех изменений
артефакты самого проекта удалены через `cargo clean -p rust-xmpp`;
сборка и проверки выполнены заново. Старый отчёт сохранён отдельно в
VALIDATION-0.3.0.md. Машинные результаты находятся в validation-results.json.

| Проверка | Результат |
|---|---|
| `cargo test --locked` | 148 passed, 0 failed, 8 ignored |
| `cargo clippy --locked --all-targets -- -D warnings` | Успешно, без предупреждений |
| `cargo fmt --check` | Успешно |
| `cargo build --release --locked` | Успешно |
| Native storage/auth oracle | Оригинальная Prosody читает и изменяет Rust данные и пароли SHA-1/SHA-256; Rust читает результат |
| Native PEP, MUC/MAM, CSI | Оригинальные модули работают с тестовыми данными Rust; правила CSI сверяются с оригиналом |
| Native push body lookup | Оригинальный util.stanza подтверждает исключение foreign namespace и вложенного extension body |
| Native federation | Настоящая Prosody cafd74b9c5ea обменивается сообщениями с Rust по двум TCP STARTTLS + SASL EXTERNAL соединениям; trust и identity включены |
| Большой архив | Потоковое чтение архива больше 128 MiB, отдельный ignored test |
| TCP integration | Контакты/подписки, IQ routing, CSI, MAM, блокировки, OMEMO PEP, MUC, offline, SM resume и SIGTERM |
| Offline/routing regression | Отсутствующий ресурс использует bare-JID fallback; no-permanent-store доставляется offline и исключается из MAM; bodyless receipt доставляется; offline headline не создаёт ошибку |
| SASL network SHA-1/SHA-256 | Независимый SCRAM, SASL1/SASL2, SSDP, подпись сервера, неверный пароль |
| SASL2 Bind2 | Канонический модуль, inline SM/CSI/Carbons/MAM, tag/resource privacy, malformed/auth failures, same UUIDv4 replacement и изоляция аккаунтов |
| WSS/HTTPS BOSH/upload | Авторизация, bind, CSI, namespaces, контакты, сообщения, upload PUT/GET/reuse |
| BOSH disconnected retry | Настоящий TCP reset до ответа; RID повторяется во время обработки и после неё, stanza выполняется однократно |
| Data directory lock | Межпроцессный отказ, тот же inode через symlink, освобождение guard и сохранность существующих файлов |
| Shell/Python syntax | Проверено для новых/изменённых сценариев |

Из восьми ignored tests отдельно успешно выполнены семь: пять native
storage/module checks, federation с настоящей Prosody и большой архив.
Оставшийся AF_UNIX admin socket test попытались выполнить: среда запретила
bind с `Operation not permitted`. Это не проверка готовности Unix socket
на целевом Docker/хосте. In-memory admin protocol tests проходят обычно.

## Нагрузочные сценарии

Оба сценария используют отдельное тестовое хранилище, 100 настоящих тестовых
аккаунтов и 500 TLS-соединений с разными ресурсами. Авторизация — TLS + PLAIN.
Проверяются адреса отправителей, IDs и содержимое направленных сообщений.

- Без MAM: 100 раундов ping и сообщений — 50 000 ping и 50 000 доставок.
- С MAM: 10 раундов — 5000 ping, 5000 доставок и ровно 10 000 записей
  в архивах отправителей/получателей, распределённых между 100 файлами.

Сырые задержки, CPU/RSS и количество дескрипторов записаны в JSON.
Это короткие loopback-прогоны на машине разработки; они не подтверждают
длительную работу полного набора модулей или отсутствие утечек памяти.
MUC/PEP/push не нагружаются этим сценарием на всех 500 соединениях.

## Воспроизведение

```bash
bash scripts/verify-local.sh
python3 scripts/load_smoke.py --clients 500 --accounts 100 --rounds 100 --message-rounds 100
python3 scripts/load_smoke.py --clients 500 --accounts 100 --rounds 10 --message-rounds 10 --archive
```

Для native проверок нужны присланные исходники Prosody и Lua dependencies:
инструкции в scripts/prosody_compat/README.md. Docker в среде разработки
отсутствует: образ, UID/GID и Compose на целевом хосте не запускались.
Не проверены реальные Monal/Conversations/Gajim, APNs/FCM push-шлюз,
рабочие сертификаты/данные, загрузка 10 GiB, длительная нагрузка и откат
конкретной установки. Функциональные ограничения остаются в COMPATIBILITY.md.
Это экспериментальный сервер, а не подтверждённая полная замена Prosody.
