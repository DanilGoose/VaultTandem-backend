# VaultTandem для VPS

Бэкенд синхронизации для плагина VaultTandem из папки `extension`. Требуется Linux VPS со статическим публичным IPv4, Docker и Docker Compose. Откройте TCP-порты 80 и 8443. PostgreSQL и внутренний HTTP-бэкенд слушают только loopback.

## Развёртывание

```sh
umask 077
cp .env.example .env
mkdir -p secrets
test -s secrets/recovery.key || openssl rand -hex 32 > secrets/recovery.key
openssl rand -hex 24
```

В `.env` укажите публичный IPv4, почту для Let’s Encrypt и вывод последней команды в `POSTGRES_PASSWORD`. Запустите:

```sh
docker compose up -d --build
docker compose logs -f caddy
```

Сервис становится доступен по `https://IP:8443` после выпуска сертификата. Caddy получает и продлевает сертификат Let’s Encrypt на IP с профилем shortlived. При добавлении домена направьте его A-запись на VPS, откройте TCP-порт 443, заполните `SYNC_DOMAIN` и выполните `docker compose up -d`. В плагине можно оставить IP или войти по новому адресу.

## Аккаунты

```sh
docker compose run --rm xsyncctl user add alice
docker compose run --rm xsyncctl user passwd alice
```

`add` создаёт аккаунт, `passwd` устанавливает новый пароль. Обе команды спрашивают пароль в терминале. Активным устройствам нужно войти заново после смены или сброса пароля. На устройстве пользователя достаточно установить плагин и ввести адрес, логин и пароль.

## Резервное копирование

На время копирования остановите бэкенд и операции с аккаунтами. Сохраните вместе дамп PostgreSQL, том `vaulttandem_objects` и закрытый файл `secrets/recovery.key` в отдельном защищённом месте.

```sh
mkdir -p backup
docker compose stop server
docker compose exec -T postgres pg_dump -U xsync -Fc xsync > backup/postgres.dump
docker run --rm -v vaulttandem_objects:/data:ro -v "$PWD/backup:/backup" alpine \
  tar -czf /backup/objects.tar.gz -C /data .
cp -p secrets/recovery.key backup/recovery.key
docker compose start server
```

Для восстановления запустите только PostgreSQL в чистом экземпляре, загрузите дамп через `pg_restore`, восстановите архив в том объектов и верните тот же ключ в `secrets/recovery.key`. Запустите сервисы и войдите с тестового клиента. Владелец VPS может использовать ключ восстановления для доступа к заметкам. Обычный бэкенд получает зашифрованные объекты, а ключ восстановления доступен контейнеру `xsyncctl`.

## Проверки

`go test ./...` проверяет сервер. Для интеграционного теста входа, изоляции, статистики и сброса пароля задайте `XSYNC_ACCOUNT_TEST_DSN` с адресом отдельного тестового PostgreSQL на `127.0.0.1`.

Исходная версия — [xSync 0.2.3](https://github.com/deku0818/xSync/tree/0.2.3), лицензия MIT.
