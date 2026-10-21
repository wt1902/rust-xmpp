# 0.8.4 — разблокировка SM store и deferred online durability

## Сервер больше не «замирает» на медленном диске

Версия 0.8.3 удерживала глобальный `Store.slots` mutex на весь durable commit
(включая fsync/append). fsync одного канала задерживал SM-коммиты всех остальных
сессий; при медленном диске и нескольких пользователях это выглядело как «сервер
перестал отвечать на запросы» и секундная доставка сообщений.

- Глобальная блокировка разделена: короткий lock `slots` теперь только
  валидирует token/limits и резервирует слот; сам append+fsync идёт под
  per-session `wal` lock. Один медленный канал больше не блокирует остальных.
- Ротация/compaction/GC сериализуются отдельным `maintenance` lock вне любого
  per-session lock — очереди append и compaction для одного WAL не гонки,
  дедлоков нет, инварианты durable и crash-тесты сохранены.
- Все существующие crash/latency/recovery regressions зелёные без изменений.

## Prosody-совместимый streaming durability (опция)

Для genuinely медленного диска (VPS с медленным fsync) добавлена опция как в
Prosody, где исходящие SM-stanza живого клиента идут в in-memory smqueue без
fsync, а durable пишутся счётчик/h и переход в hibernation.

- `smacks_online_durable = false` (strict — default): live-сессии не fsync на
  каждый outbound/ack, а помечают `dirty`; фоновый проход
  `smacks_flush_interval` (default1с) и offline-переход фиксируют durable.
- Offline/hibernating цели в любом режиме фиксируются durable ДО доставки —
  сохраняются критичные инварианты («Alice отправила, Bob ещё не авторизован»)
  и crash-регрессии; отзыв токенов/expiry остаётся durable.
- Pre-ACK durable гарантию даёт строгий режим; deferred — компромисс Prosody
  «низкая задержка» в обмен на ограниченное окно потери для online-пиров.

## Проверка

- `cargo test --locked --release`: 54 binary, 336 passed, 11 ignored (0 fail).
- Strict crash (`slow_storage_crash_network`), latency (`slow_storage_latency`),
  `sm_restart`, `journal_recovery_sync`, личная доставка — все зелёные.
- Новые регрессии: `tests/deferred_sm_online_network.py` (wire, deferred режим:
  offline durable до ACK, online доставка + flush persist), два Rust unit-теста
  в `tests/sm_journal.rs` (deferred online commit/flush, offline durable).
- `push_latency_network.py` в этой среде падает на TLS CA `keyUsage` из-за более
  строгого TLS в Python 3.14 (до SM-кода, не связано с этим изменением).

Документация: [docs/DURABLE-MESSAGE-IO.md](docs/DURABLE-MESSAGE-IO.md),
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).
