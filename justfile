default: help

dc_prefix := "COMPOSE_BAKE=true docker compose -f docker-compose.yml"

help:
    @echo 'Usage: just [recipe]'
    @echo ''
    @echo 'Recipes:'
    @just --list

dc +args:
    {{dc_prefix}} {{args}}
