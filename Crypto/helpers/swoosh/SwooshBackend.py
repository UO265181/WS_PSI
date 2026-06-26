from __future__ import annotations

import hashlib

from abc import ABC, abstractmethod
from typing import Any, Tuple, List

class SwooshBackend(ABC):
    """
    Clase base abstracta para los backends del protocolo SWOOSH.
    Define el contrato mínimo que debe ofrecer cualquier backend concreto
    y proporciona lógica común reutilizable.
    """

    @abstractmethod
    def setup_A(self, seed_A: bytes) -> Any:
        """
        Construye la estructura pública A a partir de la semilla pública.
        """
        ...

    @abstractmethod
    def keygen(self, A: Any) -> Tuple[Any, Any]:
        """
        Genera el par de claves (sk, pk) en el formato interno del backend.
        """
        ...

    @abstractmethod
    def serialize_sk(self, sk: Any) -> bytes:
        """
        Serializa la clave secreta al formato binario usado por el framework.
        """
        ...

    @abstractmethod
    def deserialize_sk(self, buf: bytes) -> Any:
        """
        Reconstruye la clave secreta a partir de su representación serializada.
        """
        ...

    @abstractmethod
    def serialize_pk(self, pk: Any) -> bytes:
        """
        Serializa la clave pública al formato binario usado por el framework.
        """
        ...

    @abstractmethod
    def deserialize_pk(self, buf: bytes) -> Any:
        """
        Reconstruye la clave pública a partir de su representación serializada.
        """
        ...

    @abstractmethod
    def derive_shared_key(
        self,
        my_sk: bytes,
        my_pk: bytes,
        peer_pk: bytes,
    ) -> bytes:
        """
        Deriva la shared key a partir del material local y de la clave pública del peer.
        """
        ...

    @abstractmethod
    def offset_poly(self, label: bytes, pk1: bytes, pk2: bytes) -> Any:
        """
        Calcula el polinomio de offset r ∈ R_q.
        """
        ...

    @abstractmethod
    def kprime(self, peer_pk: Any, my_sk: Any, r: Any) -> Any:
        """
        Calcula el valor preliminar k' ∈ R_q.
        """
        ...

    @abstractmethod
    def reconcile(self, kv_poly: Any) -> bytes:
        """
        Reconciliación final de k' para obtener una secuencia binaria.
        """
        ... 

    # ------------------------------------------------------------------
    # Auxiliar
    # ------------------------------------------------------------------
    def cardinality_by_bytes(
        self,
        my_public: bytes,
        pk_peer_bytes: bytes,
    ) -> Tuple[bytes, bytes]:
        """
        Fija un orden canónico entre las claves públicas serializadas.
        """
        my_first = my_public < pk_peer_bytes
        pk1 = my_public if my_first else pk_peer_bytes
        pk2 = pk_peer_bytes if my_first else my_public
        return pk1, pk2
    
    def sample_cbd_coeffs(self, label: bytes, seed: bytes, nonce: int, eta: int) -> List[int]:
        """
        Genera una lista de coeficientes con distribución CBD a partir de una semilla y un nonce.
        Se utiliza para muestrear tanto secretos como errores del protocolo.
        """
        total_bits = self.d * 2 * eta
        total_bytes = (total_bits + 7) // 8
        buf = self._shake(
            self.p.domain_base,
            label,
            seed,
            int(nonce).to_bytes(4, "little"),
            outlen=total_bytes,
        )

        def get_bit(bit_index: int) -> int:
            byte_i = bit_index >> 3
            bit_i = bit_index & 7
            return (buf[byte_i] >> bit_i) & 1

        coeffs: List[int] = []
        bitpos = 0
        for _ in range(self.d):
            a = 0
            b = 0
            for _ in range(eta):
                a += get_bit(bitpos)
                bitpos += 1
            for _ in range(eta):
                b += get_bit(bitpos)
                bitpos += 1
            coeffs.append((a - b) % self.q)
        return coeffs
    
    def _shake(self, *parts: bytes, outlen: int) -> bytes:
        """
        Concatena varias entradas y devuelve la salida de SHAKE-256.
        """
        h = hashlib.shake_256()
        for p in parts:
            h.update(p)
        return h.digest(outlen)
    