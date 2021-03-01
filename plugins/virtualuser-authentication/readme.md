# setup dev env

## passthrough testing, W/O SSL, password auth
```shell
export PGDATA=/tmp/pg_data_passthrough
initdb --locale=en_US.UTF-8 -E UTF8 --auth-host=password --auth-local=peer
openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:4096 \
  -keyout $PGDATA/server.key -out $PGDATA/server.crt \
  -subj  "/CN=localhost/"
postgres -k $PGDATA -h 127.0.0.1 -p 5430 -l -c logging_collector=off  -c log_min_messages=DEBUG3 &
sleep 1
psql -h "$PGDATA"  -p 5430 postgres <<EOF
CREATE DATABASE test;
CREATE ROLE plaintestrole WITH ENCRYPTED PASSWORD 'plaintestpassword' LOGIN;
GRANT ALL PRIVILEGES ON DATABASE test TO plaintestrole;
EOF
```

## SCRAM testing, with SSL

```shell
export PGDATA=/tmp/pg_data
initdb --locale=en_US.UTF-8 -E UTF8 --auth-host=scram-sha-256 --auth-local=peer
sed -i 's/^host /hostssl /' $PGDATA/pg_hba.conf

openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:4096 \
  -keyout $PGDATA/server.key -out $PGDATA/server.crt \
  -subj  "/CN=localhost/"

# postgres -k $PGDATA -h 127.0.0.1 -p 2345  -c logging_collector=off  -c ssl=true -c log_min_messages=DEBUG3 &
postgres -k $PGDATA -h 127.0.0.1 -p 2345 -l -c logging_collector=off &

sleep 2
psql -h "$PGDATA"  -p 2345 postgres <<EOF
set password_encryption = 'scram-sha-256';
CREATE DATABASE test;
CREATE ROLE test WITH ENCRYPTED PASSWORD 'test' LOGIN;
GRANT ALL PRIVILEGES ON DATABASE test TO test;
EOF

```

# check dev env

```bash
TESSQL='select inet_server_addr(), current_user, now(), session_user;'
psql  "postgresql://test:test@127.0.0.1:2345/test?sslmode=require"                -c "$TESSQL"
psql  "postgresql://zoo:pass1@127.0.0.1:5432/test?sslmode=require"                -c "$TESSQL"
psql  "postgresql://arni:pass2@127.0.0.1:5432/test?sslmode=require"               -c "$TESSQL"
psql  "postgresql://username:securepassword@127.0.0.1:5432/test?sslmode=require"  -c "$TESSQL"
psql  "postgresql://zoo1:pass1@127.0.0.1:5432/test?sslmode=require"               -c "$TESSQL"
psql  "postgresql://arni2:pass3@127.0.0.1:5432/test?sslmode=require"              -c "$TESSQL"
```
```shell
$ psql  "postgresql://test:test@127.0.0.1:2345/test?sslmode=require"                -c "$TESSQL"
 inet_server_addr | current_user |              now              | session_user 
------------------+--------------+-------------------------------+--------------
 127.0.0.1        | test         | 2021-03-01 02:01:29.742703+01 | test
(1 row)

$ psql  "postgresql://zoo:pass1@127.0.0.1:5432/test?sslmode=require"                -c "$TESSQL"
 inet_server_addr | current_user |              now              | session_user 
------------------+--------------+-------------------------------+--------------
 127.0.0.1        | test         | 2021-03-01 02:01:29.778373+01 | test
(1 row)

$ psql  "postgresql://arni:pass2@127.0.0.1:5432/test?sslmode=require"               -c "$TESSQL"
 inet_server_addr | current_user |              now              | session_user 
------------------+--------------+-------------------------------+--------------
 127.0.0.1        | test         | 2021-03-01 02:01:29.809285+01 | test
(1 row)

$ psql  "postgresql://username:securepassword@127.0.0.1:5432/test?sslmode=require"  -c "$TESSQL"
 inet_server_addr | current_user |              now              | session_user 
------------------+--------------+-------------------------------+--------------
 127.0.0.1        | test         | 2021-03-01 02:01:29.844133+01 | test
(1 row)

$ psql  "postgresql://zoo1:pass1@127.0.0.1:5432/test?sslmode=require"               -c "$TESSQL"
 inet_server_addr | current_user  |              now              | session_user  
------------------+---------------+-------------------------------+---------------
 127.0.0.1        | plaintestrole | 2021-03-01 02:01:29.872634+01 | plaintestrole
(1 row)

$ psql  "postgresql://arni2:pass3@127.0.0.1:5432/test?sslmode=require"              -c "$TESSQL"
 inet_server_addr | current_user  |              now              | session_user  
------------------+---------------+-------------------------------+---------------
 127.0.0.1        | plaintestrole | 2021-03-01 02:01:30.372406+01 | plaintestrole
(1 row)

```
