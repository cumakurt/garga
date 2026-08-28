#!/usr/bin/env bash
# Exercise every garga command against local Docker Elasticsearch 8.19.20 nodes
# and produce README screenshots plus sample PDF reports.
#
# Required containers (loopback only):
#   garga-feature-demo-es      127.0.0.1:19200  security enabled
#   garga-feature-demo-es-anon 127.0.0.1:19201  security disabled
# Set GARGA_DEMO_PASSWORD to the secured node's elastic password.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/bin/garga"
WORKDIR="${ROOT}/build/docker-demo"
SHOTS="${ROOT}/docs/screenshots"
SAMPLE="${ROOT}/sample"
RENDER="${ROOT}/scripts/render_terminal_shot.py"
ES_URL="http://127.0.0.1:19200"
ES_ANON_URL="http://127.0.0.1:19201"
PASSWORD="${GARGA_DEMO_PASSWORD:?GARGA_DEMO_PASSWORD is required}"
export ES_PASSWORD="$PASSWORD"

redact() {
  sed -e "s/${PASSWORD}/[redacted]/g" -e 's/GargaDemo-TestOnly-2026!/[redacted]/g'
}

capture() {
  local slug="$1"
  local title="$2"
  local display_cmd="$3"
  shift 3
  local out="${WORKDIR}/logs/${slug}.txt"
  local shot="${SHOTS}/${slug}.png"
  mkdir -p "${WORKDIR}/logs" "$SHOTS"
  local rc=0
  set +e
  "$@" >"${WORKDIR}/logs/${slug}.stdout" 2>"${WORKDIR}/logs/${slug}.stderr"
  rc=$?
  set -e
  {
    echo "exit=${rc}"
    if [[ -s "${WORKDIR}/logs/${slug}.stdout" ]]; then
      echo "----- stdout -----"
      cat "${WORKDIR}/logs/${slug}.stdout"
    fi
    if [[ -s "${WORKDIR}/logs/${slug}.stderr" ]]; then
      echo "----- stderr -----"
      cat "${WORKDIR}/logs/${slug}.stderr"
    fi
  } | redact >"$out"
  python3 "$RENDER" --title "$title" --command "$display_cmd" --input "$out" --output "$shot"
  echo "captured ${slug} exit=${rc} shot=${shot}"
  return 0
}

copy_latest_pdf() {
  local pattern="$1"
  local dest="$2"
  local latest
  latest="$(ls -1t ${pattern} 2>/dev/null | head -1 || true)"
  if [[ -z "$latest" ]]; then
    echo "missing PDF matching ${pattern}" >&2
    return 1
  fi
  cp -f "$latest" "$dest"
  chmod 644 "$dest"
  echo "copied $(basename "$latest") -> $dest"
}

mkdir -p "$WORKDIR" "$SHOTS" "$SAMPLE"
cd "$WORKDIR"
rm -f "${WORKDIR}/baseline-1.json" "${WORKDIR}/baseline-2.json" "${WORKDIR}/evidence.zip"

if [[ ! -x "$BIN" ]]; then
  echo "build garga first" >&2
  exit 1
fi

echo "waiting for Elasticsearch at ${ES_URL}"
for _ in $(seq 1 90); do
  if curl -sf -u "elastic:${PASSWORD}" "${ES_URL}/_security/_authenticate" >/dev/null; then
    health="$(curl -sf -u "elastic:${PASSWORD}" "${ES_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" || true)"
    if echo "$health" | grep -Eq '"status":"(green|yellow)"'; then
      echo "elasticsearch is ready"
      break
    fi
  fi
  sleep 2
done
curl -sf -u "elastic:${PASSWORD}" "${ES_URL}/_security/_authenticate" >/dev/null

echo "waiting for anonymous Elasticsearch at ${ES_ANON_URL}"
for _ in $(seq 1 90); do
  health="$(curl -sf "${ES_ANON_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" || true)"
  if echo "$health" | grep -Eq '"status":"(green|yellow)"'; then
    echo "anonymous elasticsearch is ready"
    break
  fi
  sleep 2
done
curl -sf "${ES_ANON_URL}/" >/dev/null

openssl genpkey -algorithm ED25519 -out "${WORKDIR}/evidence-private.pem" 2>/dev/null
openssl pkey -in "${WORKDIR}/evidence-private.pem" -pubout -out "${WORKDIR}/evidence-public.pem"

capture version "garga version" "garga version" \
  "$BIN" version

capture help "garga help" "garga --help" \
  "$BIN" --help

capture fingerprint "Product fingerprint" "garga fingerprint http://127.0.0.1:19201 --no-progress" \
  "$BIN" fingerprint "$ES_ANON_URL" --no-progress --rate 20 --per-host-rate 10

capture scan "Anonymous GET-only scan" "garga scan http://127.0.0.1:19201 --format console --no-progress" \
  "$BIN" scan "$ES_ANON_URL" --format console --no-progress --rate 20 --per-host-rate 10
"$BIN" scan "$ES_ANON_URL" --format jsonl --no-progress --rate 20 --per-host-rate 10 > "${WORKDIR}/scan.jsonl"

capture vuln "Signature-only CVE matching" "garga vuln http://127.0.0.1:19201 --format console --no-progress" \
  "$BIN" vuln "$ES_ANON_URL" --format console --no-progress --rate 20 --per-host-rate 10

capture auth-check "Single credential verification" "garga auth-check http://127.0.0.1:19200 --username elastic --password-stdin" \
  bash -c "printf '%s\n' \"\$ES_PASSWORD\" | \"$BIN\" auth-check \"$ES_URL\" --username elastic --password-stdin"

capture auth-check-invalid "Rejected credential" "garga auth-check http://127.0.0.1:19200 --username elastic --password-stdin" \
  bash -c "printf 'wrong-password-not-real\n' | \"$BIN\" auth-check \"$ES_URL\" --username elastic --password-stdin"

capture auth-audit "Bounded credential audit" "garga auth-audit http://127.0.0.1:19200 --credentials-stdin" \
  bash -c "printf 'basic elastic wrong-pass\nbasic elastic %s\n' \"\$ES_PASSWORD\" | \"$BIN\" auth-audit \"$ES_URL\" --credentials-stdin --max-attempts 4"

capture auth-detect "Credential stuffing detection" "garga auth-detect http://127.0.0.1:19200 --mode stuffing --credentials-stdin" \
  bash -c "printf 'basic elastic wrong-pass\nbasic elastic %s\n' \"\$ES_PASSWORD\" | \"$BIN\" auth-detect \"$ES_URL\" --mode stuffing --credentials-stdin --max-attempts 4"

printf '%s\n' elastic guest > "${WORKDIR}/spray-users.txt"
printf '%s\n' wrong-one "$PASSWORD" > "${WORKDIR}/spray-passwords.txt"
capture auth-detect-spraying "Password spraying detection" "garga auth-detect http://127.0.0.1:19200 --mode spraying --users-file spray-users.txt --passwords-file spray-passwords.txt" \
  "$BIN" auth-detect "$ES_URL" --mode spraying --users-file "${WORKDIR}/spray-users.txt" --passwords-file "${WORKDIR}/spray-passwords.txt" --max-attempts 8 --spray-delay 0s

printf '%s\n' wrong-one "$PASSWORD" > "${WORKDIR}/wordlist.txt"
capture auth-detect-dictionary "Dictionary detection" "garga auth-detect http://127.0.0.1:19200 --mode dictionary --username elastic --wordlist wordlist.txt" \
  "$BIN" auth-detect "$ES_URL" --mode dictionary --username elastic --wordlist "${WORKDIR}/wordlist.txt" --max-attempts 8

# Native Elasticsearch passwords are at least 6 characters; charset generation caps at
# length 4, so the live brute-force demo uses an operator password list that includes
# the accepted secret after two invalid candidates.
printf '%s\n' 0000 1234 "$PASSWORD" > "${WORKDIR}/bf-passwords.txt"
capture auth-detect-brute-force "Bounded brute-force detection" "garga auth-detect http://127.0.0.1:19200 --mode brute-force --username elastic --passwords-file passwords.txt" \
  "$BIN" auth-detect "$ES_URL" --mode brute-force --username elastic --passwords-file "${WORKDIR}/bf-passwords.txt" --max-attempts 8

capture health "Authenticated health assessment" "garga health http://127.0.0.1:19200 --username elastic --password-stdin --format terminal" \
  bash -c "printf '%s\n' \"\$ES_PASSWORD\" | \"$BIN\" health \"$ES_URL\" --username elastic --password-stdin --allow-plaintext-auth --format terminal --requests-per-second 20 --snapshot-out \"${WORKDIR}/baseline-1.json\" --force"

capture assess "Authenticated security assessment" "garga assess http://127.0.0.1:19200 --username elastic --password-stdin --format json" \
  bash -c "printf '%s\n' \"\$ES_PASSWORD\" | \"$BIN\" assess \"$ES_URL\" --username elastic --password-stdin --allow-plaintext-auth --format json --requests-per-second 20"

capture secrets-generate "Synthetic secret fixtures" "garga secrets generate --target http://127.0.0.1:19200 --user elastic --password-env ES_PASSWORD" \
  "$BIN" secrets generate --target "$ES_URL" --user elastic --password-env ES_PASSWORD --allow-plaintext-auth --rate-limit 20

# Documents are searchable after refresh.
curl -sf -u "elastic:${PASSWORD}" -X POST "${ES_URL}/garga-sensitive-test/_refresh" >/dev/null

capture secrets "Sensitive-data discovery" "garga secrets --target http://127.0.0.1:19200 --user elastic --password-env ES_PASSWORD --format table --indices garga-sensitive-test" \
  "$BIN" secrets --target "$ES_URL" --user elastic --password-env ES_PASSWORD --allow-plaintext-auth --format table --indices garga-sensitive-test --include-system-indices --rate-limit 20 --sample-size 100 --timeout 2m
python3 - <<'PY'
from pathlib import Path
log = Path("logs/secrets.txt")
lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
header, body, in_table = ["exit=0", "----- stdout -----"], [], False
for line in lines:
    if line.startswith("SEVERITY"):
        in_table = True
    if in_table:
        body.append(line)
Path("logs/secrets-table.txt").write_text("\n".join(header + body) + "\n", encoding="utf-8")
PY
python3 "$RENDER" --title "Sensitive-data findings table" --command "garga secrets --target http://127.0.0.1:19200 --user elastic --password-env ES_PASSWORD --format table --indices garga-sensitive-test" --input "${WORKDIR}/logs/secrets-table.txt" --output "${SHOTS}/secrets-table.png" --max-rows 72

capture report "Offline JSONL report" "garga report --format csv --input scan.jsonl" \
  "$BIN" report --format csv --input "${WORKDIR}/scan.jsonl"

python3 - <<'PY'
from pathlib import Path
src = Path("scan.jsonl")
lines = [line for line in src.read_text().splitlines() if line.strip()]
baseline = Path("diff-baseline.jsonl")
current = Path("diff-current.jsonl")
if lines:
    baseline.write_text("\n".join(lines[: max(1, len(lines)//2)]) + "\n")
    current.write_text("\n".join(lines) + "\n")
else:
    baseline.write_text("")
    current.write_text("")
PY

capture diff "Finding lifecycle diff" "garga diff --baseline diff-baseline.jsonl --current diff-current.jsonl" \
  "$BIN" diff --baseline "${WORKDIR}/diff-baseline.jsonl" --current "${WORKDIR}/diff-current.jsonl" --format console --fail-on none

python3 - <<'PY'
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
src = Path("baseline-1.json")
data = json.loads(src.read_text())
later = data.copy()
ts = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
later["timestamp"] = (ts + timedelta(minutes=15)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
later["cluster_store_bytes"] = int(data.get("cluster_store_bytes") or 0) + 8 * 1024 * 1024
nodes = later.get("nodes") or {}
for node in nodes.values():
    total = int(node.get("disk_total_bytes") or 0)
    avail = int(node.get("disk_available_bytes") or 0)
    if total <= 0:
        node["disk_total_bytes"] = 100 * 1024 * 1024 * 1024
        node["disk_available_bytes"] = 60 * 1024 * 1024 * 1024
    else:
        node["disk_available_bytes"] = max(0, avail - 8 * 1024 * 1024)
later["nodes"] = nodes
Path("baseline-2.json").write_text(json.dumps(later, indent=2) + "\n")
PY

capture forecast "Disk-threshold forecast" "garga forecast baseline-1.json baseline-2.json" \
  "$BIN" forecast "${WORKDIR}/baseline-1.json" "${WORKDIR}/baseline-2.json" --format console

# Evidence pack uses a sample PDF produced by health/scan.
health_pdf="$(ls -1t garga-health-*.pdf garga-assessment-*.pdf 2>/dev/null | head -1 || true)"
if [[ -z "$health_pdf" ]]; then
  echo "health PDF missing for evidence pack" >&2
  exit 1
fi
rm -f "${WORKDIR}/evidence.zip"
capture evidence-pack "Evidence bundle" "garga evidence pack --file report.pdf --output evidence.zip" \
  "$BIN" evidence pack --file "$health_pdf" --file "${WORKDIR}/baseline-1.json" --output "${WORKDIR}/evidence.zip" --signing-key "${WORKDIR}/evidence-private.pem" --format console

capture evidence-verify "Evidence verification" "garga evidence verify evidence.zip --public-key evidence-public.pem" \
  "$BIN" evidence verify "${WORKDIR}/evidence.zip" --public-key "${WORKDIR}/evidence-public.pem" --format console

mkdir -p "${WORKDIR}/unsigned-bundle"
printf '{"schema_version":"0.1","version":"demo","archive_sha256":"%s","files":[]}\n' "$(printf 'a%.0s' {1..64})" > "${WORKDIR}/unsigned-bundle/manifest.json"
printf '00' > "${WORKDIR}/unsigned-bundle/manifest.sig"
printf 'PK\x05\x06' > "${WORKDIR}/unsigned-bundle/signatures.zip"
capture update "Signed signature update (unsigned bundle rejected)" "garga update --source unsigned-bundle --dir signatures" \
  "$BIN" update --source "${WORKDIR}/unsigned-bundle" --dir "${WORKDIR}/signatures"

copy_latest_pdf "garga-scan-*.pdf" "${SAMPLE}/garga-scan-sample.pdf"
copy_latest_pdf "garga-health-*.pdf" "${SAMPLE}/garga-health-sample.pdf"
copy_latest_pdf "garga-assessment-*.pdf" "${SAMPLE}/garga-assessment-sample.pdf"
copy_latest_pdf "garga-secrets-*.pdf" "${SAMPLE}/garga-secrets-sample.pdf"

cat > "${WORKDIR}/results.md" <<EOF
Docker Elasticsearch: ${ES_URL} (8.19.20, security enabled, HTTP)
Commands captured under docs/screenshots/
Sample PDFs under sample/
EOF

echo "demo complete"
