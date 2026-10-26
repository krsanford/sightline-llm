"""Per-install, name-constrained root CA.

mitmproxy would otherwise generate an unconstrained CA: if its key ever leaked, it could impersonate any website
to this Mac while trusted. This CA carries an X.509 NameConstraints extension (critical) that permits only the LLM
API domains Sightline decrypts, so verifiers reject any certificate it signs for anything else, even one minted
with a stolen key. Written in mitmproxy's confdir layout before mitmproxy starts, so mitmproxy adopts it.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# DNS name constraints match the name itself and every subdomain of it.
PERMITTED_DNS = [
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "openai.azure.com",
    "api.mistral.ai", "api.groq.com", "api.x.ai", "api.deepseek.com", "openrouter.ai", "api.together.xyz",
]


def ensure_ca(certs_dir: Path, common_name: str = "Sightline Local CA") -> bool:
    """Create the constrained CA if no CA exists yet. Returns True if a new CA was created."""
    key_pem, cert_pem = certs_dir / "mitmproxy-ca.pem", certs_dir / "mitmproxy-ca-cert.pem"
    if key_pem.exists():
        return False
    certs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sightline (this Mac only)")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.NameConstraints(permitted_subtrees=[x509.DNSName(d) for d in PERMITTED_DNS],
                                            excluded_subtrees=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption())
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    fd = os.open(key_pem, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:          # mitmproxy layout: key + cert in one file
        fh.write(key_bytes + cert_bytes)
    cert_pem.write_bytes(cert_bytes)
    return True


def is_constrained(cert_path: Path) -> bool:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    try:
        ext = cert.extensions.get_extension_for_class(x509.NameConstraints)
    except x509.ExtensionNotFound:
        return False
    return ext.critical and bool(ext.value.permitted_subtrees)
