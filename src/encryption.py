import os
import ssl
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

def get_ssl_context(ip: str) -> ssl.SSLContext:
        cert_dir = os.path.join(os.path.expanduser("~"), ".p2p_file_share")
        cert_path = os.path.join(cert_dir, "cert.pem")
        key_path = os.path.join(cert_dir, "key.pem")

        # Generate certs if needed
        if not is_cert_valid(cert_path, ip) or not os.path.exists(key_path):
            os.makedirs(cert_dir, exist_ok=True)
            generate_cert(cert_path, key_path, ip)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return context

def generate_cert(cert_path: str, key_path: str, ip: str):
    # Generate ECDSA private key
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"p2p-file-share"),
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
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.IPAddress(ipaddress.IPv4Address(ip))
            ]),
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

def is_cert_valid(cert_path: str, current_ip: str) -> bool:
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Check if it's expired
        if cert.not_valid_after_utc <= datetime.now(timezone.utc):
            return False

        # Check if it matches the current IP
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)

        if not any(str(ip) == current_ip for ip in ips):
            return False

        return True
    except Exception:
        return False
