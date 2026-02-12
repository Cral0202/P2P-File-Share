from dataclasses import dataclass

@dataclass
class HostInfo:
    ip: str
    port: int
    cert_fingerprint: str
    upnp_enabled: bool
