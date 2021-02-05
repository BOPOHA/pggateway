# setup dev env

```shell
export PGDATA=/tmp/pg_data
SOCKETDIR=$(mktemp -d -t initdb-XXXXXXXXXX)

initdb --locale=en_US.UTF-8 -E UTF8

echo '
hostssl all all 127.0.0.1/32 md5
local   all all trust
' > /tmp/pg_data/pg_hba.conf

openssl req -x509 -nodes -sha256 -days 3650 -newkey rsa:4096 \
  -keyout $PGDATA/server.key -out $PGDATA/server.crt \
  -subj  "/C=US/ST=NY/L=New York/O=Org, Inc./OU=DT/CN=localhost/emailAddress=root@localhost"

postgres -k "$SOCKETDIR" -h 127.0.0.1 -p 2345 -F -c logging_collector=off  -c ssl=true &

sleep 5
psql -h "$SOCKETDIR"  -p 2345 postgres <<EOF
set password_encryption = 'md5';
CREATE DATABASE test;
CREATE ROLE test WITH ENCRYPTED PASSWORD 'test' LOGIN;
GRANT ALL PRIVILEGES ON DATABASE test TO test;
EOF

```

# check dev env

```shell
psql  "postgresql://test:test@127.0.0.1:2345/test?sslmode=require"
psql  "postgresql://zoo:pass1@127.0.0.1:5432/test?sslmode=require"
```
