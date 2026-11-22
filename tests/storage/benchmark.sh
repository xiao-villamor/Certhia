#!/bin/sh
# Run from a PostgreSQL 17 client environment against a seeded disposable database.
# Connection details come from libpq (PGHOST, PGDATABASE, PGUSER, etc.).
set -eu
queries=$(cd "$(dirname "$0")/queries" && pwd)
logs=$(mktemp -d)
trap 'rm -rf "$logs"' EXIT
cd "$logs"
repos=$(psql -XAtq -v ON_ERROR_STOP=1 -c 'SELECT count(*) FROM repositories')
printf '%-24s %10s %10s\n' 'Query' 'p50 (ms)' 'p95 (ms)'
for query in "$queries"/*.sql; do
    pgbench -n -c 1 -t 10 -D "repositories=$repos" -f "$query" >/dev/null
    pgbench -n -c 1 -t 100 -D "repositories=$repos" -f "$query" -l --log-prefix=sample >/dev/null
    # pgbench per-transaction logs report elapsed microseconds in column three.
    awk '{print $3}' sample.* | sort -n | awk -v name="$(basename "$query" .sql)" '
        NR==50 {median=$1} NR==95 {printf "%-24s %10.3f %10.3f\n",name,median/1000,$1/1000}
        END {if (NR!=100) exit 1}'
    rm sample.*
done
