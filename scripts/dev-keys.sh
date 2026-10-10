#!/usr/bin/env sh
set -eu
mkdir -p .dev-keys
if [ -e .dev-keys/jwt-private.pem ] || [ -e .dev-keys/jwt-public.pem ]; then
  echo "Refusing to overwrite existing development keys" >&2
  exit 1
fi
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out .dev-keys/jwt-private.pem
openssl pkey -in .dev-keys/jwt-private.pem -pubout -out .dev-keys/jwt-public.pem
chmod 600 .dev-keys/jwt-private.pem
echo "Development-only RSA keys generated in .dev-keys/"
