import os
import ssl
import base64
from typing import Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

CERT_HOSTNAME: str = "p2p-node"

def get_cert_and_key() -> Tuple[str, str]:
    cert_dir = os.path.join(os.path.expanduser("~"), ".p2p_file_share")
    cert_path = os.path.join(cert_dir, "cert.pem")
    key_path = os.path.join(cert_dir, "key.pem")

    # Generate new ones if needed
    if not is_cert_valid(cert_path) or not os.path.exists(key_path):
        os.makedirs(cert_dir, exist_ok=True)
        generate_cert_and_key(cert_path, key_path)

    return cert_path, key_path

def get_ssl_context(client_auth: bool) -> ssl.SSLContext:
    cert_path, key_path = get_cert_and_key()

    if client_auth:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        mode = ssl.CERT_NONE # TODO: Change
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        mode = ssl.CERT_NONE

    context.check_hostname = False # Since we use fingerprints, we can disable this
    context.verify_mode = mode
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context

def generate_cert_and_key(cert_path: str, key_path: str):
    # Generate ECDSA private key
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "p2p-file-share"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(CERT_HOSTNAME)]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    # Write private key to file
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write certificate to file
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def is_cert_valid(cert_path: str) -> bool:
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Check if it's expired
        return cert.not_valid_after_utc > datetime.now(timezone.utc)
    except Exception:
        return False

def get_cert_fingerprint(cert_path: str) -> str:
    with open(cert_path, "rb") as f:
        cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    fingerprint = cert.fingerprint(hashes.SHA256())

    # Base64 encode it to reduce length
    return base64.b64encode(fingerprint).decode("ascii")

def is_cert_fingerprint_trusted(fingerprint: str) -> bool:
    # TODO: Implement
    return True
