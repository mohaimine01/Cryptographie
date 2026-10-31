#!/usr/bin/env bash
# Renouvelle le certificat du serveur s'il expire dans moins de 30 jours.
# Usage : renouveler.sh [--force]   (à lancer en root : écrit dans /etc/nginx/tls)
set -euo pipefail

PKI=${PKI:-$(cd "$(dirname "$0")/../tp2" && pwd)}   # dossier de la PKI du TP 2
DEST=${DEST:-/etc/nginx/tls}
SEUIL=$((30 * 86400))

if [[ "${1:-}" != "--force" ]] && \
   openssl x509 -checkend "$SEUIL" -noout -in "$DEST/serveur_chaine.crt" >/dev/null 2>&1; then
  echo "le certificat vaut encore plus de 30 jours, rien à faire"
  exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 1. nouvelle clé et nouvelle demande
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/serveur.key"
openssl req -new -key "$tmp/serveur.key" -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out "$tmp/serveur.csr"

# 2. signature par l'intermédiaire
(cd "$PKI" && openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in "$tmp/serveur.csr" -out "$tmp/serveur.crt")

# 3. vérification de la chaîne avant tout déploiement (set -e arrête le script en cas d'échec)
openssl verify -CAfile "$PKI/racine/racine.crt" -untrusted "$PKI/inter/inter.crt" \
  -verify_hostname www.tp.local "$tmp/serveur.crt"
cat "$tmp/serveur.crt" "$PKI/inter/inter.crt" > "$tmp/serveur_chaine.crt"

# 4. sauvegarde de l'ancien certificat, installation, rechargement
mkdir -p "$DEST/ancien"
cp -p "$DEST/serveur.key" "$DEST/serveur_chaine.crt" "$DEST/ancien/"
install -m 600 "$tmp/serveur.key" "$DEST/serveur.key"
install -m 644 "$tmp/serveur_chaine.crt" "$DEST/serveur_chaine.crt"

if nginx -t && systemctl reload nginx; then
  echo "certificat renouvelé"
else
  echo "configuration refusée, retour à l'ancien certificat" >&2
  cp -p "$DEST/ancien/serveur.key" "$DEST/ancien/serveur_chaine.crt" "$DEST/"
  systemctl reload nginx
  exit 1
fi
