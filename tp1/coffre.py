"""Mini-coffre de fichiers chiffrés (TP 1)."""
import os
import struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

FORMAT_ID = b"CFR1"
HEADER_LEN = 44   # 4 (identifiant) + 12 (t, m, p) + 16 (sel) + 12 (nonce)
TAG_LEN = 16

# temps, mémoire (Kio), parallélisme
T, M, P = 3, 64 * 1024, 4

USAGE_CHIFFREMENT = b"chiffrement"

# bornes acceptées à la lecture : les paramètres viennent du fichier, avant
# toute vérification, et ne doivent pas permettre d'épuiser la machine
T_MAX, M_MAX, P_MAX = 10, 1024 * 1024, 16


def cle_maitresse(mot_de_passe: str, sel: bytes, t: int = T, m: int = M, p: int = P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(mot_de_passe.encode(), sel, time_cost=t,
                           memory_cost=m, parallelism=p, hash_len=32,
                           type=Type.ID)


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 avec info = b"coffre-v1|" + usage -> 32 octets."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"coffre-v1|" + usage).derive(maitresse)


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes,
             t: int = T, m: int = M, p: int = P) -> bytes:
    sel = os.urandom(16)
    nonce = os.urandom(12)
    entete = FORMAT_ID + struct.pack(">III", t, m, p) + sel + nonce
    ad = entete + nom.encode()   # l'en-tête et le nom sont authentifiés
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), USAGE_CHIFFREMENT)
    return entete + AESGCM(cle).encrypt(nonce, donnees, ad)


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    if len(blob) < HEADER_LEN + TAG_LEN:
        raise ValueError("fichier trop court")
    entete = blob[:HEADER_LEN]
    if entete[:4] != FORMAT_ID:
        raise ValueError("format inconnu")
    t, m, p = struct.unpack(">III", entete[4:16])
    if not (1 <= t <= T_MAX and 8 * p <= m <= M_MAX and 1 <= p <= P_MAX):
        raise ValueError("paramètres hors limites")
    sel, nonce = entete[16:32], entete[32:44]
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), USAGE_CHIFFREMENT)
    return AESGCM(cle).decrypt(nonce, blob[HEADER_LEN:], entete + nom.encode())


def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes,
               t: int = T, m: int = M, p: int = P) -> bytes:
    """Change le mot de passe, avec sel, nonce et paramètres neufs."""
    return chiffrer(nouveau_mdp, nom, dechiffrer(ancien_mdp, nom, blob), t, m, p)
