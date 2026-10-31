"""Affiche les jours restants des certificats d'un dossier.

Code de sortie : 0 (OK), 1 (ALERTE, moins de 30 jours), 2 (CRITIQUE, moins de 7 jours).
"""
import datetime
import pathlib
import sys

from cryptography import x509

ALERTE, CRITIQUE = 30, 7


def jours_restants(cert):
    fin = cert.not_valid_after_utc
    return round((fin - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 86400)


def main(dossier):
    code = 0
    for f in sorted(pathlib.Path(dossier).glob("*.crt")):
        cert = x509.load_pem_x509_certificate(f.read_bytes())
        j = jours_restants(cert)
        if j < CRITIQUE:
            niveau, code = "CRITIQUE", 2
        elif j < ALERTE:
            niveau, code = "ALERTE", max(code, 1)
        else:
            niveau = "OK"
        print(f"{niveau:9} {j:5d} j  {cert.subject.rfc4514_string():20} {f.name}")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
