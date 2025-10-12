#!/usr/bin/env bash
set -euo pipefail

# 1) make PKCE
read -r VERIFIER CHALLENGE < <(python3 - <<'PY'
import os,base64,hashlib
v = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
print(v, c)
PY
)

# 2) get code (follow Location)
AUTH_URL="http://localhost:8000/authorize?response_type=code&client_id=spa-client&redirect_uri=http://localhost:5173/callback&scope=notes.read%20notes.write&state=xyz&code_challenge=${CHALLENGE}&code_challenge_method=S256&login=demo&password=demo"
LOC=$(curl -s -i "$AUTH_URL" | tr -d '\r' | sed -n 's/^Location: //p')
CODE=$(python3 - <<PY
import sys,urllib.parse as u
q=u.urlparse(sys.argv[1]).query
print(dict(u.parse_qsl(q))['code'])
PY "$LOC")

# 3) exchange token
AT=$(curl -s -X POST http://localhost:8000/token \
  -H 'Content-Type: application/json' \
  -d "{\"grant_type\":\"authorization_code\",\"code\":\"$CODE\",\"redirect_uri\":\"http://localhost:5173/callback\",\"client_id\":\"spa-client\",\"code_verifier\":\"$VERIFIER\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

echo "ACCESS_TOKEN=$AT"

# 4) call API
curl -s http://localhost:8001/api/notes -H "Authorization: Bearer $AT" | sed 's/^/NOTES: /'
