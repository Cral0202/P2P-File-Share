from dataclasses import dataclass

@dataclass(frozen=True)
class TransferFile:
    path: str
    name: str
    size: int # Bytes
