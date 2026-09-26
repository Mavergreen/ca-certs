# platform: host-agnostic
# spec: tests/apply.sh "not the running system" -- the applier itself decides whether $ROOT is the running system and records "keychain no" on any other volume, so this call is not inside if [ -z "$ROOT" ]
"$ROOT/usr/local/mavergreen/ca-certs/libexec/ca-certs-apply" --root "$ROOT/"
