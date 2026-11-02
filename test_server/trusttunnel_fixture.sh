#!/usr/bin/env bash
# Reproducible official endpoint on loopback only. No production credentials.
set -euo pipefail
umask 077
fixture_dir="${1:-$(mktemp -d /tmp/unbihex-trusttunnel.XXXXXX)}"
mkdir -p "$fixture_dir"
fixture_dir="$(cd "$fixture_dir" && pwd)"
for name in vpn.toml hosts.toml credentials.toml key.pem cert.pem; do
  if [[ -e "$fixture_dir/$name" ]]; then
    echo "Refusing to overwrite an existing fixture: $fixture_dir/$name" >&2
    exit 1
  fi
done
port="${TT_PORT:-19443}"
case "$port" in ''|*[!0-9]*) echo 'Invalid TT_PORT' >&2; exit 1;; esac
if (( port < 1 || port > 65535 )); then echo 'Invalid TT_PORT' >&2; exit 1; fi
url='https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-v1.1.0-linux-x86_64.tar.gz'
curl --fail --location --silent --show-error "$url" -o "$fixture_dir/endpoint.tar.gz"
printf '%s  %s\n' '91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7' "$fixture_dir/endpoint.tar.gz" | sha256sum --check --status
tar xzf "$fixture_dir/endpoint.tar.gz" -C "$fixture_dir"
binary="$fixture_dir/trusttunnel-v1.1.0-linux-x86_64/trusttunnel_endpoint"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$fixture_dir/key.pem" -out "$fixture_dir/cert.pem" -days 1 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -addext basicConstraints=critical,CA:FALSE >/dev/null 2>&1
cat > "$fixture_dir/vpn.toml" <<EOF
listen_address = "127.0.0.1:$port"
allow_private_network_connections = true
credentials_file = "$fixture_dir/credentials.toml"
[listen_protocols.http2]
EOF
cat > "$fixture_dir/hosts.toml" <<EOF
[[main_hosts]]
hostname = "localhost"
cert_chain_path = "$fixture_dir/cert.pem"
private_key_path = "$fixture_dir/key.pem"
EOF
cat > "$fixture_dir/credentials.toml" <<'EOF'
[[client]]
username = "local-test"
password = "local-test-password"
EOF
# Endpoint prints the URI followed by explanatory text: retain only the URI.
"$binary" "$fixture_dir/vpn.toml" "$fixture_dir/hosts.toml" -c local-test -a "127.0.0.1:$port" -n 'Official loopback' > "$fixture_dir/export.txt"
head -n 1 "$fixture_dir/export.txt" > "$fixture_dir/profile.txt"
python3 - "$fixture_dir" "$port" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
(p/'profile.json').write_text(json.dumps({'version':1,'hostname':'localhost','address':'127.0.0.1:'+sys.argv[2],'username':'local-test','password':'local-test-password','certificate':(p/'cert.pem').read_text(),'name':'Official JSON'}))
PY
printf 'Fixture: %s\nStart official endpoint in another terminal:\n' "$fixture_dir"
printf '%q ' "$binary" "$fixture_dir/vpn.toml" "$fixture_dir/hosts.toml" --jobs 2
printf '\nTests from repository root:\n'
printf 'TT_PROFILE=%q cargo test --locked --manifest-path unbihex-engine/Cargo.toml --test trusttunnel_official -- --ignored --nocapture\n' "$fixture_dir/profile.txt"
printf 'TT_PROFILE=%q TT_JSON_PROFILE=%q cargo test --locked --manifest-path unbihex-client/Cargo.toml -p unbihex-client-core --test trusttunnel_official -- --ignored --nocapture\n' "$fixture_dir/profile.txt" "$fixture_dir/profile.json"
