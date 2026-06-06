#!/usr/bin/env bash
# Smoke test for gen-certs.sh ↔ haproxy.cfg alignment.
#
# Runs the cert generator in a throwaway dir and asserts:
#   1. CA cert verifies the worker cert (chain is correct).
#   2. CA basicConstraints has CA:TRUE with pathlen:0 (no sub-CAs).
#   3. Worker cert has extendedKeyUsage=clientAuth (and only that).
#   4. Worker CN matches the value HAProxy's ACL is checking in haproxy.cfg.
#   5. CN regex validation rejects subject-injection / path-traversal args.
#   6. Re-running with an existing CA reuses it instead of replacing.
#
# Run from anywhere: examples/pki/test-pki.sh

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
GEN=$SCRIPT_DIR/gen-certs.sh
CFG=$SCRIPT_DIR/../haproxy/haproxy.cfg

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1" >&2; exit 1; }

# ── 1. Generate certs ────────────────────────────────────────────────
echo "→ generating fresh PKI in $tmp/pki"
"$GEN" -d "$tmp/pki" >/dev/null
[[ -f $tmp/pki/workers-ca.crt   ]] || fail "workers-ca.crt not produced"
[[ -f $tmp/pki/workers-ca.key   ]] || fail "workers-ca.key not produced"
[[ -f $tmp/pki/rhttp-worker.crt ]] || fail "rhttp-worker.crt not produced"
[[ -f $tmp/pki/rhttp-worker.key ]] || fail "rhttp-worker.key not produced"
pass "all four artifacts created"

# Private keys must be 0600
for k in workers-ca.key rhttp-worker.key; do
    mode=$(stat -c '%a' "$tmp/pki/$k")
    [[ "$mode" == "600" ]] || fail "$k mode is $mode, expected 600"
done
pass "private keys are 0600"

# ── 2. Chain verifies ────────────────────────────────────────────────
openssl verify -CAfile "$tmp/pki/workers-ca.crt" "$tmp/pki/rhttp-worker.crt" >/dev/null \
    || fail "worker cert does not verify against CA"
pass "worker cert chains to CA"

# ── 3. CA constraints: CA:TRUE, pathlen:0 ────────────────────────────
ca_text=$(openssl x509 -in "$tmp/pki/workers-ca.crt" -noout -text)
grep -q "CA:TRUE" <<<"$ca_text" || fail "CA cert missing CA:TRUE"
grep -q "pathlen:0" <<<"$ca_text" || fail "CA cert missing pathlen:0 (sub-CAs would be possible)"
pass "CA has basicConstraints CA:TRUE, pathlen:0"

# ── 4. Worker EKU = clientAuth ───────────────────────────────────────
worker_text=$(openssl x509 -in "$tmp/pki/rhttp-worker.crt" -noout -text)
grep -q "TLS Web Client Authentication" <<<"$worker_text" \
    || fail "worker cert missing clientAuth EKU"
grep -q "TLS Web Server Authentication" <<<"$worker_text" \
    && fail "worker cert unexpectedly has serverAuth EKU"
pass "worker cert has clientAuth EKU only"

# ── 5. CN ↔ haproxy.cfg ACL alignment ────────────────────────────────
worker_cn=$(openssl x509 -in "$tmp/pki/rhttp-worker.crt" -noout -subject -nameopt RFC2253 \
    | sed -n 's/.*CN=\([^,]*\).*/\1/p')
[[ -n "$worker_cn" ]] || fail "could not extract CN from worker cert"

acl_cn=$(grep -E '^\s*acl\s+is_worker\s+ssl_c_s_dn\(CN\)\s+-m\s+str' "$CFG" \
    | awk '{print $NF}')
[[ -n "$acl_cn" ]] || fail "could not find is_worker ACL in $CFG"

if [[ "$worker_cn" != "$acl_cn" ]]; then
    fail "CN mismatch: cert CN='$worker_cn' but haproxy.cfg ACL expects '$acl_cn'"
fi
pass "cert CN ('$worker_cn') matches haproxy.cfg ACL"

# ── 6. CN regex validation rejects bad input ─────────────────────────
for bad in '../etc/passwd' 'x/O=Acme' 'has space' 'semi;colon' ''; do
    if "$GEN" -d "$tmp/bad" "$bad" >/dev/null 2>&1; then
        fail "gen-certs.sh accepted invalid CN: '$bad'"
    fi
done
rm -rf "$tmp/bad"
pass "invalid CNs are rejected"

# ── 7. Idempotent CA reuse ───────────────────────────────────────────
ca_fp_before=$(openssl x509 -in "$tmp/pki/workers-ca.crt" -noout -fingerprint -sha256)
"$GEN" -d "$tmp/pki" extra-worker >/dev/null
ca_fp_after=$(openssl x509 -in "$tmp/pki/workers-ca.crt" -noout -fingerprint -sha256)
[[ "$ca_fp_before" == "$ca_fp_after" ]] || fail "CA was regenerated on second run"
[[ -f $tmp/pki/extra-worker.crt ]] || fail "second worker cert not produced"
openssl verify -CAfile "$tmp/pki/workers-ca.crt" "$tmp/pki/extra-worker.crt" >/dev/null \
    || fail "second worker cert does not verify against reused CA"
pass "re-running reuses existing CA and mints new workers"

echo
echo "all checks passed."
