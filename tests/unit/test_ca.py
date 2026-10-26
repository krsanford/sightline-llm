"""The per-install CA can only vouch for LLM API domains (X.509 name constraints), even with its own key."""
import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sightline.ca import ensure_ca, is_constrained


@pytest.fixture(scope="module")
def ca(tmp_path_factory):
    d = tmp_path_factory.mktemp("certs")
    assert ensure_ca(d) is True and ensure_ca(d) is False      # idempotent: never replaces an existing CA
    assert oct((d / "mitmproxy-ca.pem").stat().st_mode & 0o777) == "0o600"
    return d


def mint(ca_dir, host):
    """Sign a leaf for `host` with the CA's own private key — what an attacker holding the key would do."""
    cakey = serialization.load_pem_private_key((ca_dir / "mitmproxy-ca.pem").read_bytes(), None)
    cacert = x509.load_pem_x509_certificate((ca_dir / "mitmproxy-ca-cert.pem").read_bytes())
    k = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    c = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
         .issuer_name(cacert.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(cakey.public_key()), critical=False)
         .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .sign(cakey, hashes.SHA256()))
    return k, c


def handshake(ca_dir, host, tmp_path) -> str:
    k, c = mint(ca_dir, host)
    (tmp_path / "c.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        try:
            sctx.wrap_socket(conn, server_side=True).recv(1)
        except (ssl.SSLError, OSError):
            pass
    threading.Thread(target=serve, daemon=True).start()
    cctx = ssl.create_default_context(cafile=str(ca_dir / "mitmproxy-ca-cert.pem"))
    try:
        with cctx.wrap_socket(socket.create_connection(srv.getsockname()), server_hostname=host):
            return "accepted"
    except ssl.SSLCertVerificationError as e:
        return f"rejected: {e.verify_message}"
    finally:
        srv.close()


def test_ca_carries_critical_name_constraints(ca):
    assert is_constrained(ca / "mitmproxy-ca-cert.pem")


@pytest.mark.parametrize("host", ["api.openai.com", "api.anthropic.com", "myco.openai.azure.com"])
def test_llm_hosts_validate(ca, host, tmp_path):
    assert handshake(ca, host, tmp_path) == "accepted"


@pytest.mark.parametrize("host", ["example.com", "www.mybank.com", "accounts.google.com", "openai.com.evil.tld"])
def test_other_hosts_rejected_even_with_the_ca_key(ca, host, tmp_path):
    result = handshake(ca, host, tmp_path)
    assert result.startswith("rejected") and "subtree" in result.lower(), result
