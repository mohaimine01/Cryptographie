#!/usr/bin/env bash
# Reconstruit toute la PKI du TP 2 (étapes 2 à 4) dans ce dossier.
set -euo pipefail
cd "$(dirname "$0")"

rm -rf racine inter
mkdir -p racine/{crl,newcerts} inter/{crl,newcerts}
touch racine/index.txt inter/index.txt
echo 1000 > racine/serial;    echo 1000 > inter/serial
echo 1000 > racine/crlnumber; echo 1000 > inter/crlnumber

# AC racine : P-384, 10 ans
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

# AC intermédiaire : P-256, 5 ans, signée par la racine
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
openssl req -new -key inter/inter.key -subj "/C=BF/O=Universite TP/CN=Inter TP" \
  -out inter/inter.csr
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

# serveur
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur.csr -out serveur.crt

# clients alice et bob
for u in alice bob; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $u.key
  openssl req -new -key $u.key -subj "/CN=$u@tp.local" \
    -addext "subjectAltName=email:$u@tp.local" -out $u.csr
  openssl ca -batch -config inter.cnf -extensions ext_client -days 90 \
    -in $u.csr -out $u.crt
done

openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -purpose sslclient alice.crt bob.crt
