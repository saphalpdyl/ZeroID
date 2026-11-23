#!/bin/sh
# Runs once, the first time the Postgres container starts with an empty volume.
# 1. Creates the least-privilege app role using a password from the environment.
# 2. Applies every migration in db/migrations in order.
set -eu

if [ -z "${ZEROID_APP_DB_PASSWORD:-}" ]; then
  echo "ZEROID_APP_DB_PASSWORD is not set" >&2
  exit 1
fi

# psql variables (:'pw') quote the password safely instead of pasting it into SQL.
psql -v ON_ERROR_STOP=1 -v pw="$ZEROID_APP_DB_PASSWORD" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE zeroid_app LOGIN PASSWORD :'pw';
SQL

for f in /zeroid-db/migrations/*.sql; do
  echo "Applying $f"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$f"
done
