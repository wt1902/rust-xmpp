# Проверка изменения CI

2026-10-20. Изменяется только CI, упаковка Docker и документация; Rust source
и версия0.8.0 не менялись. Предыдущие293 теста относятся к этому Rust source.

Локально успешно:

- actionlint1.7.7: `.github/workflows/ci.yml` без ошибок;
- bash -n для всех трёх CI shell scripts;
- Python compile и проверка генерации default-branch/version/SHA tags;
- отклонение чужой ветки, несовпадающей версии, URL вместо hostname,
  некорректного image path и отсутствующего token;
- SHA-256 bundled reference archive совпадает с ожидаемым.

Docker daemon отсутствует; GitHub Actions и реальный push в Gitea здесь
не запускались. Результат следует проверить первым workflow run после
добавления репозитория, variables и secrets по GITHUB-ACTIONS.md.
