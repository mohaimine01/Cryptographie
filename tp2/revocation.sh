#!/usr/bin/env bash
# Étape 5 (certificat hors domaine) et étape 6 (révocation d'Alice), après pki.sh.
set -euo pipefail
cd "$(dirname "$0")"

# certificat pour www.example.com : signé, mais refusé à la validation
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out example.key
openssl req -new -key example.key -subj "/CN=www.example.com" \
  -addext "subjectAltName=DNS:www.example.com" -out example.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in example.csr -out example.crt

# la clé d'Alice est compromise
openssl ca -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
