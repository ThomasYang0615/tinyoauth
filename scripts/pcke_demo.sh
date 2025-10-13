#!/usr/bin/env bash
set -euo pipefail

# 1) make PKCE (43–128 chars, base64url, no padding)
read -r VERIFIER CHALLENGE < <(python3 - <<'PY'
import os,base64,hashlib
v = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
print(v, c)
PY
)

# 2) get code (do NOT follow redirect; just read Location)
STATE="xyz"
AUTH_URL="http://localhost:8000/authorize?response_type=code&client_id=spa-client&redirect_uri=http://localhost:5173/callback&scope=notes.read%20notes.write&state=${STATE}&code_challenge=${CHALLENGE}&code_challenge_method=S256&login=demo&password=demo"

LOC=$(curl -sS -o /dev/null -w '%{redirect_url}' "$AUTH_URL")
[ -n "$LOC" ] || { echo "No Location header found (did /authorize return 302?)"; exit 1; }

# parse code & state and verify
read -r CODE GOT_STATE <<<"$(python3 - <<'PY' "$LOC"
import sys, urllib.parse as u
q = dict(u.parse_qsl(u.urlparse(sys.argv[1]).query))
print(q.get('code',''), q.get('state',''))
PY
)"
[ -n "$CODE" ] || { echo "No code in redirect URI"; exit 1; }
[ "$GOT_STATE" = "$STATE" ] || { echo "State mismatch! expected '$STATE', got '$GOT_STATE'"; exit 1; }

# 3) exchange token
TOKEN_JSON="$(curl -sSf -X POST http://localhost:8000/token \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d "{\"grant_type\":\"authorization_code\",\"code\":\"$CODE\",\"redirect_uri\":\"http://localhost:5173/callback\",\"client_id\":\"spa-client\",\"code_verifier\":\"$VERIFIER\"}")"

# extract access_token (and fail clearly if not present)
AT="$(python3 - <<'PY' "$TOKEN_JSON"
import sys, json
try:
    data = json.loads(sys.argv[1])
    print(data["access_token"])
except Exception as e:
    print("Bad token response:", sys.argv[1], file=sys.stderr)
    raise
PY
)"
echo "ACCESS_TOKEN=$AT"

# 4) call API
curl -sS http://localhost:8001/api/notes -H "Authorization: Bearer $AT" | sed 's/^/NOTES: /'
