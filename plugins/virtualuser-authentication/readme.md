# setup dev env

```shell
export PGDATA=/tmp/pg_data
initdb --locale=en_US.UTF-8 -E UTF8 --auth-host=scram-sha-256 --auth-local=peer
sed -i 's/^host /hostssl /' $PGDATA/pg_hba.conf

openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:4096 \
  -keyout $PGDATA/server.key -out $PGDATA/server.crt \
  -subj  "/CN=localhost/"

# postgres -k $PGDATA -h 127.0.0.1 -p 2345  -c logging_collector=off  -c ssl=true -c log_min_messages=DEBUG3 &
postgres -k $PGDATA -h 127.0.0.1 -p 2345 -l -c logging_collector=off &

sleep 5
psql -h "$PGDATA"  -p 2345 postgres <<EOF
set password_encryption = 'scram-sha-256';
CREATE DATABASE test;
CREATE ROLE test WITH ENCRYPTED PASSWORD 'test' LOGIN;
GRANT ALL PRIVILEGES ON DATABASE test TO test;
EOF

```

# check dev env

```shell
psql  "postgresql://test:test@127.0.0.1:2345/test?sslmode=require"
psql  "postgresql://zoo:pass1@127.0.0.1:5432/test?sslmode=require"
psql  "postgresql://arni:pass2@127.0.0.1:5432/test?sslmode=require"
psql  "postgresql://username:securepassword@127.0.0.1:5432/test?sslmode=require"

```
