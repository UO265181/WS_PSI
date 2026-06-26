from __future__ import annotations
from typing import Any, Tuple


class PswooshFFIClient:
    """
    Cliente FFI real para el módulo Rust pswoosh_ffi.
      - Carga el módulo nativo
      - Expone una interfaz Python
      - Convierte resultados a bytes
    """

    def __init__(self):
        import pswoosh_ffi
        self.lib = pswoosh_ffi

    @property
    def symbytes(self) -> int:
        return int(self.lib.SYMBYTES)

    @property
    def publickey_bytes(self) -> int:
        return int(self.lib.PUBLICKEY_BYTES)

    @property
    def secretkey_bytes(self) -> int:
        return int(self.lib.SECRETKEY_BYTES)

    def setup_a(self, seed_a: bytes, f: bool = False) -> Any:
        if len(seed_a) != self.symbytes:
            raise ValueError(
                f"setup_a: seed_a debe tener {self.symbytes} bytes y recibió {len(seed_a)}"
            )
        return self.lib.setup_a_py(seed_a, f)

    def keygen(self, a_handle: Any, f: bool = False) -> Tuple[bytes, bytes]:
        sk, pk = self.lib.keygen_py(a_handle, f)
        return bytes(sk), bytes(pk)

    def shared_key(self, my_sk: bytes, my_pk: bytes, peer_pk: bytes, f: bool = False) -> bytes:
        k = self.lib.shared_key_py(my_sk, my_pk, peer_pk, f)
        return bytes(k)