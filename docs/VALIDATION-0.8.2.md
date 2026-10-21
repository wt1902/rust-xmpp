# Проверка0.8.2

2026-10-21, Linux x86_64, Rust1.99.1. Итоговый единый прогон:
[verify.txt](validation-logs-0.8.2/verify.txt). Machine-readable report:
[validation-results.json](validation-results.json).

|Проверка|Результат|
|---|---|
|Rust ordinary tests|305passed,0failed,11ignored|
|fmt / Clippy all-targets -D warnings / release|Успешно|
|Новые Rust regressions|6archive endpoints/recovery/limits +2account-lock/duplicateACK — успешно|
|Личная доставка|6fixtures:100000MAM/user, roster0/5000/10000,500SMpending, default/native CSI — успешно|
|Неподвижный push gateway|Настоящий STARTTLS; hibernating+offline: bothmessagesdurable, senderACKh=4 до ответа gateway; offline сохранён до первого postTLSstream|
|Bind2 и MAM metadata|100000records,5reconnects+5IQ, exactIDs/timestamps — успешно|
|Сетевые регрессии|Весь verify-local.sh, включаяprivate WSS/BOSH chat, PEP/push,AndroidSASL,MUCcrash/SMrestart,S3/migration — успешно|
|Native reference|8module/storage +1TLS/SASL EXTERNAL federation — успешно|
|Общая нагрузка|500TLS,100accounts,5000ping,5000messages,10000MAM,failures=[]|
|MUC+SM нагрузка|500resources,10rooms,25000presence,1500messages,SIGKILL+10resume — успешно|

MUC+SM total 45.54с, peak sampled RSS 40.94MiB.

Воспроизведение личного push-stall: прежний0.8.1 за2с сохраняет только первое
сообщение и не отвечаетSMACK при зависшем postTLSfeatures gateway. Новый0.8.2
сохраняет оба и отвечаетh=4 в том же2сокне; тестовое окно не является latency SLA.
Offline ordering baseline проверен на0.8.0; его точный hash указан отдельно.

Bind2 authenticate→success median2742.353→1.976мс; metadataIQ2437.945→0.355мс.
Baseline0.8.0hash74882319… содержит тот же прежний scan path. Все raw samples,
IDs, timestamps и hashes — validation-logs-0.8.2/bind2-*.json.

Default inactive OMEMO доставлен за2.58–4.06мс, receipts7.36–35.56мс в checked
fixtures; explicit[] сохраняет удержание доactive. Намеренный CSI dwell2с
отдельно обозначен в отчёте и не выдаётся за время вычисления/доставки.
Каждый personalarchive содержит ровно100523records/user. Детали и настройка:
[PERSONAL-MESSAGE-LATENCY.md](PERSONAL-MESSAGE-LATENCY.md).

Release SHA-256: `130431025c4c7c2f72e28b77a31c83867f857ef8bb56d1f71b10e4b19d7caaf5`. Все новые final reports содержат этот hash.
Команда: `XMPP_LOAD_CHECK=1 bash scripts/verify-local.sh` с native env согласно
scripts/prosody_compat/README.md. Использованы CARGO_INCREMENTAL=0,
CARGO_PROFILE_DEV_DEBUG=0, CARGO_PROFILE_TEST_DEBUG=0. Перед итоговым прогоном
устранены stale package linker artifacts очисткой package build outputs;
исходники не менялись после финальной сборки. Воспроизведение прошло одним
последующим полным прогоном; preliminary compiler errors не являются test failures.

Это loopback, не production клиента/диска/сети. Fsync и durable commit до
подтверждения сохранены; boundedpushqueue не обещает durable notification delivery.
SMglobalIOmutex, полные MAMqueries и maintenance остаются отдельной стоимостью.
9nativeignoredtests выполнены; остальные AF_UNIX/largearchiveignoredtests и
10GiBtransfers в этом локальном прогоне не запускались (полный CI entrypoint
по-прежнему включает их). Старые largeupload результаты не приписываются0.8.2.
Общие границы: [COMPATIBILITY.md](COMPATIBILITY.md).
