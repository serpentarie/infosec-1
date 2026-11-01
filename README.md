# Защищенное REST API

Учебный API заметок на Python и Flask. Данные хранятся в SQLite, зависимости устанавливаются через pip.

## Запуск

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
flask --app api:create_app init-db
flask --app api:create_app create-user --username alice
waitress-serve --listen=127.0.0.1:8000 --call api:create_app
```

Пароль задается при создании пользователя.

## API

| Метод | Описание |
|---|---|
| `POST /auth/login` | Принимает `username` и `password`, возвращает JWT |
| `GET /api/data` | Возвращает заметки текущего пользователя |
| `POST /api/data` | Принимает `text`, создает заметку |

Получение токена:

```bash
curl http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"ВАШ_ПАРОЛЬ"}'
```

Создание и получение заметок:

```bash
curl http://127.0.0.1:8000/api/data \
  -H 'Authorization: Bearer ВАШ_JWT' \
  -H 'Content-Type: application/json' \
  -d '{"text":"Первая заметка"}'

curl http://127.0.0.1:8000/api/data \
  -H 'Authorization: Bearer ВАШ_JWT'
```

Без токена защищенные методы возвращают `401 Unauthorized`.

## Меры защиты

- **SQLi:** пользовательские значения передаются через параметры SQL-запросов, без конкатенации строк.
- **XSS:** текст заметок экранируется через `html.escape` при возврате в JSON.
- **Аутентификация:** пароли хэшируются алгоритмом scrypt с солью. После входа выдается JWT на 15 минут. На защищенных методах проверяются подпись, алгоритм, срок действия, issuer и audience. Ключ подписи берется из переменной окружения `JWT_SECRET`.
- **Доступ:** пользователь может создавать и читать только собственные заметки.

## CI/CD

GitHub Actions запускает проверки при push и pull request:

- **Bandit** — статический анализ кода (SAST).
- **Snyk** — проверка зависимостей (SCA).

Отчеты сохраняются в artifacts. API проверен через curl: вход возвращает `200`, создание заметки — `201`, доступ без JWT — `401`.

## Результаты CI

[Успешный запуск pipeline без предупреждений](https://github.com/serpentarie/infosec-1/actions/runs/41329306542).

Тесты, Bandit, pip-audit и Snyk завершились успешно.
Bandit не обнаружил проблем в коде, pip-audit — известных уязвимостей зависимостей,
Snyk — уязвимостей высокого и критического уровня.

Общий результат запуска и сохраненные артефакты:

![Общий результат CI](docs/screenshots/image.png)

Успешный шаг SAST:

![Bandit SAST](docs/screenshots/image-1.png)

Отчет Bandit: ошибки анализа и найденные проблемы отсутствуют.

![Отчет Bandit](docs/screenshots/image-2.png)

Успешный шаг SCA:

![Snyk SCA](docs/screenshots/image-4.png)

JSON-отчет Snyk:

![Отчет Snyk](docs/screenshots/image-3.png)
