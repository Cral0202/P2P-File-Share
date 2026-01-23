from dataclasses import dataclass

@dataclass
class HostInfo:
    ip: str
    port: int
    upnp_enabled: bool
