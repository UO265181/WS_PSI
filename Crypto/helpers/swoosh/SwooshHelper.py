from __future__ import annotations

import base64
import hashlib
from typing import Any, Dict, Optional, Tuple, Union

from Crypto.helpers.CSHelper import CSHelper
from .params import SwooshParameters
from .SwooshBackendFlint import BackendFlint
from .SwooshBackendNTTBasic import BackendNTTBasic
from .SwooshBackendRust import BackendRust


PublicKeyIn = Union[str, bytes, Dict[str, str]]


class SwooshHelper(CSHelper):
    """
    Helper del protocolo SWOOSH.

    Puente entre el framework y el backend criptográfico
    concreto, encapsulando la generación de claves, la serialización
    del material criptográfico y la derivación de la shared key.
    """

    def __init__(self, backend: Optional[str] = None, params: Optional[SwooshParameters] = None):
        """
        Inicializa el helper y selecciona el backend correspondiente.

        Si no se indica ningún backend, se utiliza FLINT por defecto.
        Tras la inicialización, genera automáticamente el material
        criptográfico inicial del nodo.
        """
        self.category = "SWOOSH"

        if params is None:
            self.params = SwooshParameters()
        else:
            self.params = params

        if backend is None or backend == "FLINT":
            self.backend = BackendFlint(self.params)
            self.imp_name = "SWOOSH_FLINT"
        elif backend == "NTT":
            self.backend = BackendNTTBasic(self.params)
            self.imp_name = "SWOOSH_NTT"
        elif backend == "RUST":
            self.backend = BackendRust(self.params)
            self.imp_name = "SWOOSH_RUST"
        else:
            raise ValueError(f"Backend de SWOOSH no válido: {backend}")

        self.A: Any = None
        self._sk: Any = None
        self.public_key: Any = None
        self.shared_key: Optional[bytes] = None

        self.generate_keys()

    # ----------------------------
    # Formato de claves
    # ----------------------------
    def _short_hash(self, data: bytes, n_hex: int = 16) -> str:
        """
        Devuelve una huella determinista truncada a partir de SHA-256.
        """
        return hashlib.sha256(data).hexdigest()[:n_hex]

    def _b64encode(self, raw: bytes) -> str:
        """
        Codifica un bloque de bytes en base64 ASCII.
        """
        return base64.b64encode(raw).decode("ascii")

    def _b64decode(self, s: str) -> bytes:
        """
        Decodifica una cadena base64 y lanza una excepción si no es válida.
        """
        try:
            return base64.b64decode(s)
        except Exception as exc:
            raise ValueError("Clave pública en base64 inválida") from exc

    def serialize_public_key(self) -> str:
        """
        Serializa la clave pública actual y la devuelve como cadena base64.
        """
        self._ensure_keys()
        pk_bytes = self.backend.serialize_pk(self.public_key)
        return self._b64encode(pk_bytes)

    def reconstruct_public_key(self, public_key_in: PublicKeyIn) -> bytes:
        """
        Reconstruye una clave pública de entrada y la normaliza a bytes.
        """
        return self._coerce_public_bytes(public_key_in)

    def _coerce_public_bytes(self, data: PublicKeyIn) -> bytes:
        """
        Convierte distintas representaciones de clave pública a bytes.
        """
        if isinstance(data, dict):
            data = data.get("public_key", "")
        if isinstance(data, str):
            return self._b64decode(data) if data else b""
        return data

    def serialize_result(self, result: bytes, _type: Optional[str] = None) -> Dict[str, str]:
        """
        Serializa el resultado criptográfico para su almacenamiento o envío.
        """
        if result is None:
            return {"shared_key": ""}
        return {"shared_key": self._b64encode(result)}

    def public_key_for_ui(self) -> str:
        """
        Devuelve una representación breve de la clave pública para la IU web.
        """
        if self.public_key is None:
            return "Public key not generated yet"

        pk_bytes = self.backend.serialize_pk(self.public_key)
        return f"{self._short_hash(pk_bytes, 16)}"

    # ----------------------------
    # Setup
    # ----------------------------
    def setup_A(self, seed: Optional[bytes] = None) -> None:
        """
        Genera la matriz pública A a partir de una semilla.
        """
        seed_A = seed if seed is not None else self.params.seed_A
        self.A = self.backend.setup_A(seed_A)

    def generate_keys(
        self,
        _bit_length: Optional[int] = None,  # ignorado, se mantiene por compatibilidad
        _domain: Optional[str] = None       # ignorado, se mantiene por compatibilidad
    ) -> Tuple[bytes, bytes]:
        """
        Genera el par de claves del nodo y devuelve sus serializaciones.
        """
        print(f"Generating {self.imp_name} Keys...")

        if self.A is None:
            self.setup_A()

        sk, pk = self.backend.keygen(self.A)
        self._sk = sk
        self.public_key = pk
        self.shared_key = None

        sk_bytes = self.backend.serialize_sk(sk)
        pk_bytes = self.backend.serialize_pk(pk)

        print(f"{self.imp_name} Keys Generated")
        return sk_bytes, pk_bytes

    # ----------------------------
    # SdK
    # ----------------------------
    def compute_shared_key(self, peer_public: PublicKeyIn) -> bytes:
        """
        Wrapper para el handler que garantiza la existencia de claves
        antes de derivar la shared key.
        """
        self._ensure_keys()
        return self.derive_shared_key(peer_public)

    def _ensure_keys(self) -> None:
        """
        Garantiza que existen clave secreta y clave pública locales.
        """
        if self._sk is None or self.public_key is None:
            self.generate_keys()

    def derive_shared_key(
        self,
        peer_public: PublicKeyIn,
        *,
        my_public: Optional[bytes] = None,
        my_secret: Optional[bytes] = None,
    ) -> bytes:
        """
        Deriva la shared key a partir del material dado o el local y de la clave pública del peer.
        """
        pk_peer_bytes = self._coerce_public_bytes(peer_public)

        if my_public is None:
            if self.public_key is None:
                raise ValueError("derive_shared_key: falta mi clave pública. Llama a generate_keys() antes.")
            my_public = self.backend.serialize_pk(self.public_key)

        if my_secret is None:
            if self._sk is None:
                raise ValueError("derive_shared_key: falta mi secreto. Llama a generate_keys() antes.")
            my_secret = self.backend.serialize_sk(self._sk)

        if not pk_peer_bytes:
            raise ValueError("derive_shared_key: peer_public está vacío o mal formado.")

        self.shared_key = self.backend.derive_shared_key(my_secret, my_public, pk_peer_bytes)
        return self.shared_key

    # ----------------------------
    # Debug
    # ----------------------------
    def debug_fingerprint_pk(self, n_hex: int = 16) -> str:
        """
        Devuelve una huella corta de la clave pública actual.
        """
        if self.public_key is None:
            return "pk:<none>"
        pk_bytes = self.backend.serialize_pk(self.public_key)
        return f"pk:{self._short_hash(pk_bytes, n_hex)}"

    def debug_fingerprint_sk(self, n_hex: int = 16) -> str:
        """
        Devuelve una huella corta de la clave secreta actual.
        """
        if self._sk is None:
            return "sk:<none>"
        sk_bytes = self.backend.serialize_sk(self._sk)
        return f"sk:{self._short_hash(sk_bytes, n_hex)}"

    def debug_fingerprint_shared(self, n_hex: int = 16) -> str:
        """
        Devuelve una huella corta de la shared key actual, si existe.
        """
        if self.shared_key is None:
            return "k:<none>"
        return f"k:{self._short_hash(self.shared_key, n_hex)}"