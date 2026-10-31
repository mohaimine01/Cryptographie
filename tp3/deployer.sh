#!/usr/bin/env bash
# Étapes 1 et 2 : installe la chaîne, la clé, la racine, la CRL et la configuration nginx.
# À lancer avec sudo, après tp2/pki.sh et tp2/revocation.sh.
set -euo pipefail
PKI="$(cd "$(dirname "$0")/../tp2" && pwd)"

cat "$PKI/serveur.crt" "$PKI/inter/inter.crt" > "$PKI/serveur_chaine.crt"
mkdir -p /etc/nginx/tls
install -m 600 "$PKI/serveur.key" /etc/nginx/tls/serveur.key
install -m 644 "$PKI/serveur_chaine.crt" "$PKI/racine/racine.crt" "$PKI/crls.pem" /etc/nginx/tls/
grep -q www.tp.local /etc/hosts || echo "127.0.0.1 www.tp.local" >> /etc/hosts

install -m 644 "$(dirname "$0")/nginx.conf" /etc/nginx/conf.d/tp.conf
nginx -t
systemctl reload nginx
