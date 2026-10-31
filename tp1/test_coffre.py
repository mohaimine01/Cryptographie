import pytest
from cryptography.exceptions import InvalidTag
from coffre import (chiffrer, dechiffrer, rechiffrer, cle_maitresse, sous_cle,
                    HEADER_LEN)

# paramètres légers pour garder des tests rapides
LEGER = dict(t=1, m=8 * 1024, p=2)


def test_aller_retour():
    b = chiffrer("correct horse", "notes.txt", b"secret", **LEGER)
    assert dechiffrer("correct horse", "notes.txt", b) == b"secret"


def test_aller_retour_vide():
    b = chiffrer("pw", "vide.txt", b"", **LEGER)
    assert dechiffrer("pw", "vide.txt", b) == b""


def test_aller_retour_parametres_par_defaut():
    b = chiffrer("pw", "a.dat", b"donnees")
    assert dechiffrer("pw", "a.dat", b) == b"donnees"


def test_deux_chiffrements_differents():
    b1 = chiffrer("pw", "a", b"x", **LEGER)
    b2 = chiffrer("pw", "a", b"x", **LEGER)
    assert b1 != b2
    assert b1[16:32] != b2[16:32]   # sels
    assert b1[32:44] != b2[32:44]   # nonces


def test_mauvais_mot_de_passe():
    b = chiffrer("pw", "a", b"x", **LEGER)
    with pytest.raises(InvalidTag):
        dechiffrer("autre", "a", b)


def test_octet_modifie():
    b = bytearray(chiffrer("pw", "a", b"x" * 100, **LEGER))
    b[HEADER_LEN + 5] ^= 1
    with pytest.raises(InvalidTag):
        dechiffrer("pw", "a", bytes(b))


def test_nom_echange():
    b = chiffrer("pw", "salaires.xlsx", b"x", **LEGER)
    with pytest.raises(InvalidTag):
        dechiffrer("pw", "menu.txt", b)


@pytest.mark.parametrize("pos", [11, 17, 33])   # mémoire, sel, nonce
def test_entete_modifie(pos):
    b = bytearray(chiffrer("pw", "a", b"x", **LEGER))
    b[pos] ^= 1
    with pytest.raises(InvalidTag):
        dechiffrer("pw", "a", bytes(b))


def test_parametres_demesures_refuses():
    b = bytearray(chiffrer("pw", "a", b"x", **LEGER))
    b[5] ^= 0xFF   # t devient énorme : refusé avant toute dérivation
    with pytest.raises(ValueError):
        dechiffrer("pw", "a", bytes(b))


def test_format_inconnu():
    b = bytearray(chiffrer("pw", "a", b"x", **LEGER))
    b[0:4] = b"CFR2"
    with pytest.raises(ValueError):
        dechiffrer("pw", "a", bytes(b))


def test_rechiffrer():
    b = chiffrer("ancien", "a.tar", b"contenu", **LEGER)
    n = rechiffrer("ancien", "nouveau", "a.tar", b, t=2, m=16 * 1024, p=2)
    with pytest.raises(InvalidTag):
        dechiffrer("ancien", "a.tar", n)
    assert dechiffrer("nouveau", "a.tar", n) == b"contenu"


def test_sous_cles_distinctes():
    k = cle_maitresse("pw", b"0123456789abcdef", **LEGER)
    assert k == cle_maitresse("pw", b"0123456789abcdef", **LEGER)
    assert len(k) == 32
    assert sous_cle(k, b"chiffrement") != sous_cle(k, b"authentification")
