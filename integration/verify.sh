#!/usr/bin/env bash
# Verificação da Fase A (rodar DEPOIS do up com override).
# Falha com exit != 0 no primeiro check que não retornar 200.
set -u
BASE="${BASE:-http://localhost:8080}"
API="${API:-http://localhost:8000}"
ok()  { echo "OK   $1 -> $2"; }
fail() { echo "FAIL $1 -> $2 (esperado 200)"; exit 1; }
check() { code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$1"); [ "$code" = "200" ] && ok "$1" "$code" || fail "$1" "$code"; }

check "$BASE/encyclopedia/index.html"
check "$BASE/encyclopedia/groups.html"
check "$BASE/encyclopedia/actor.html?id=apt29"
check "$BASE/encyclopedia/threat-model.html"
check "$BASE/encyclopedia/data/actors.json"
check "$BASE/encyclopedia/data/cvc.json"
check "$API/health"
check "$BASE/"
echo "ALL CHECKS PASSED"
