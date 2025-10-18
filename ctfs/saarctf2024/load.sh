#!/bin/sh

docker compose exec -T postgres psql -h localhost -U postgres < ./upstream/db.sql
