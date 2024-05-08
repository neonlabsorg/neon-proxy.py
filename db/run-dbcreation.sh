#!/bin/bash
COMPONENT="dbcreation"
echo \{\"level\": \"INFO\", \"date\": \"$(date "+%F %X.%3N")\", \"module\": \"$(basename "$0"):${LINENO}\"\}, \"process\": $!, \"message\": \"Start ${COMPONENT} service\"\}

export PGPASSWORD=${POSTGRES_PASSWORD}
psql -h ${POSTGRES_HOST} ${POSTGRES_DB} ${POSTGRES_USER} -a -f db/scheme.sql
psql -h ${POSTGRES_HOST} ${POSTGRES_DB} ${POSTGRES_USER} --command "\\dt+ public.*"
psql -h ${POSTGRES_HOST} ${POSTGRES_DB} ${POSTGRES_USER} --command "\\d+ public.*"
