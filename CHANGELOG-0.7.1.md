# 0.7.1 — cached SASL2 inline fallback and Gajim discovery

По предоставленному журналу TLS завершался успешно, а SASL2 запрос отклонялся
inline validator до проверки SCRAM/PLAIN credentials. В исходниках обоих Android
клиентов Quickstart использует сохранённую доступность inline Bind2 и может
посылать bind после того, как текущая конфигурация перестала его объявлять.
Сервер 0.7.0 возвращал malformed-request для отключённого Bind2. Дополнительная
ошибка регистра в mapper скрывала `bind2 is disabled` за invalid-inline-fields.

Теперь отключённые optional Bind2/inline SM requests игнорируются, обычная
проверка credentials выполняется, и сервер возвращает post-auth features для
legacy bind. Модуль Bind2 остаётся явно включаемым: ложной рекламы capability
нет. Реализованный путь соответствует проверенному fallback клиентского кода.
Malformed requests включённых расширений по-прежнему отклоняются; wrong password
не принимается. События sasl-attempt/inline-options доступны до validation,
ignored extension отмечается inline-request-ignored; причины parser errors уточнены.

Добавлены host/account disco features XEP-0258 и XEP-0077, которые проверяют
SecurityLabels/Register modules Gajim. Register discovery означает также
смену пароля/отмену регистрации: allow_registration=false по-прежнему запрещает
создание новых аккаунтов, но не управление своим существующим аккаунтом.
Security label catalog отражает requested @to в обеих версиях. Для точной
policy/classifications схемы предоставленного конфига добавлен catalog-only
adapter: выбирает default_policy, показывает classification names/display/default;
не реализует ACL или обязательное enforcement. Неизвестные policy fields
отклоняются. Это документированное расширение относительно supplied mod_seclabels.

Logger объединяет одинаковые destinations и маски уровней: перекрывающиеся
console правила больше не дублируют строки. Разные файлы сохраняют свои уровни.

Старый cached-inline отказ воспроизведён, новый fallback проверен реальным TLS,
SCRAM-SHA-1/PLAIN, SSDP on/off, Bind2/SM flags и bind+ping. Gajim predicates и
фактические catalog/password/create/delete операции проверены по TLS.
Реальные Android/Gajim приложения в этой среде не запускались; полный runtime
остаётся experimental с ограничениями docs/COMPATIBILITY.md.
