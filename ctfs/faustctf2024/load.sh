#!/bin/sh

docker compose exec -T postgres psql -h localhost -U postgres < ./upstream/db.sql
docker compose exec -T postgres psql -h localhost -U postgres < ./upstream/team_assoc.sql
