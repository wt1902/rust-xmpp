# GitHub Actions → private Gitea Registry

Workflow: `.github/workflows/ci.yml`. Push, pull request и ручной запуск выполняют
проверки; публикация разрешена только для основной ветки репозитория и тегов
`v<версия Cargo.toml>`. PR, включая PR из forks, не получает registry credentials.

## Настройка GitHub

Settings → Secrets and variables → Actions:

| Тип | Имя | Значение |
|---|---|---|
| Variable | `GITEA_REGISTRY` | `gitea.example.org` или `gitea.example.org:5000`, без `https://` и пути |
| Variable | `GITEA_IMAGE` | `owner/rust-xmpp`, lowercase, без registry и тега |
| Secret | `GITEA_REGISTRY_USERNAME` | Имя пользователя Gitea с правом публикации пакетов owner |
| Secret | `GITEA_REGISTRY_TOKEN` | Personal access token с правом записи packages |

Создайте private owner/organization и проверьте права чтения пакета в Gitea:
аутентифицированный push сам по себе не меняет публичность owner/package.
Registry должен быть доступен GitHub-hosted runner по HTTPS с доверенным CA.
Для registry только в LAN потребуется runner с доступом к этой сети; настройки
runs-on для image job можно заменить на labels доверенного self-hosted runner.
Не запускайте PR-код на привилегированном self-hosted runner без изоляции.

## Проверки и результат

Job `verify` на Ubuntu24.04 ставит Rust из `rust-toolchain.toml`, Python3.12,
Lua5.4, OpenSSL/ICU и собирает оригинальную bundled Prosody cafd74b9c5ea.
MinIO собирается из unmodified upstream RELEASE.2025-04-22T22-12-26Z,
Go1.24.3, с проверкой SHA-256 исходного архива. Sandbox adapter не применяется.

`scripts/ci/verify-all.sh` запускает:

- fmt, все обычные Rust tests, Clippy и release build;
- все сетевые проверки из verify-local.sh, native module/storage и federation;
- обе нагрузки500TLS, в том числе MUC+SM SIGKILL/resume;
- оставшиеся ignored tests: AF_UNIX admin socket и archive>128MiB;
- реальные10GiB PUT/GET через MinIO и через local HTTPS backend, последовательно.

Таким образом отсутствие native reference или MinIO является ошибкой, а не skip.
Нужно не менее20GiB свободного диска перед проверками. На одноразовом hosted runner
удаляются неиспользуемые Android/.NET/GHC SDK; Go caches очищаются после сборки MinIO.
Тесты могут занимать десятки минут. Timeout verify job —90минут.

Artifact `rust-xmpp-linux-amd64`: проверенный release executable и SHA256SUMS.
Artifact `test-results`: полный лог и JSON-отчёты, также при ошибке теста.
Job `image` скачивает именно этот executable, проверяет checksum и собирает
Docker target `ci-runtime`. В образе выполняются `rust-xmpp --version` и
`prosodyctl --version`, затем извлечённый executable сравнивается побайтно с artifact.
Image smoke проходит и на PR. Только после успеха выполняются login/push.

Теги:

- `sha-<полный40символьныйcommit>` — каждый публикуемый commit;
- `latest` — только основная ветка;
- `v0.8.0` — пример version tag; он должен совпадать с Cargo.toml.

Version tag не меняет latest; prerelease также не перезаписывает latest.
Собирается Linux amd64, не multiarch. Локальный `docker build .` по-прежнему
собирает source target `runtime`; CI target использует уже проверенный binary.

Workflow добавлен и проверен локально как конфигурация. Реальный GitHub-run,
Docker daemon и push в ваш Gitea здесь не выполнялись; для этого нужны репозиторий
и перечисленные настройки. CI намеренно останавливает публикацию при любой ошибке.

Документация registry: https://docs.gitea.com/usage/packages/container/
