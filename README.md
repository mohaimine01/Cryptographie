# Ingénierie de la cryptographie (EC1)

Travaux pratiques 1 à 3 : chiffrement authentifié, infrastructure de gestion de clés, canal TLS.

- `tp1/` : mini-coffre de fichiers (AES-256-GCM, Argon2id, HKDF) et ses tests.
- `tp2/` : PKI avec OpenSSL (racine, intermédiaire, serveur, clients, révocation).
- `tp3/` : serveur nginx en TLS avec authentification mutuelle, supervision et renouvellement des certificats.
- `Rapport.pdf` : compte rendu.

Les clés privées et les demandes de certificat ne sont pas versées.

## Utilisation

```bash
# TP 1 (python 3.10+, pip install cryptography argon2-cffi pytest)
cd tp1 && pytest -v

# TP 2
./tp2/pki.sh            # racine, intermédiaire, serveur, alice, bob
./tp2/revocation.sh     # certificat hors domaine, révocation d'alice

# TP 3 (nginx installé)
sudo ./tp3/deployer.sh
python3 tp3/surveiller.py tp2          # code de sortie 0, 1 ou 2
sudo ./tp3/renouveler.sh               # renouvelle si moins de 30 jours (--force pour forcer)
```
