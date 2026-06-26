from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from flint import fmpz
from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackend import SwooshBackend
from Crypto.helpers.swoosh.PswooshFFIClient import PswooshFFIClient


Sk = bytes
Pk = bytes


class QuaresmaParameterMismatchError(ValueError):
    """
    Excepción lanzada cuando los parámetros del backend no coinciden
    con los esperados por la implementación de pswoosh.
    """
    pass


@dataclass
class RustABundle:
    """
    Contenedor de estructuras A generadas por pswoosh,
    indexadas por rol/cardinalidad.
    """
    by_role: Dict[bool, Any]


@dataclass
class RustKeyBundle:
    """
    Contenedor de claves secretas y públicas generadas por el backend nativo,
    indexadas por rol/cardinalidad.
    """
    sk_by_role: Dict[bool, bytes]
    pk_by_role: Dict[bool, bytes]


class BackendRust(SwooshBackend):
    """
    Backend SWOOSH basado en la implementación pswoosh de Quaresma.

    Este backend delega las operaciones principales en pswoosh expuesto
    a través de `pswoosh_ffi`.
    """

    EXPECTED_D = 256
    EXPECTED_N = 32
    EXPECTED_Q = int(fmpz(2) ** 214 - 255)
    EXPECTED_KEY_BYTES = 32

    DEFAULT_SERIALIZATION_ROLE = True

    def __init__(self, params: SwooshParameters):
        """
        Inicializa el backend  con los parámetros del esquema.
        Crea el cliente FFI y valida que los parámetros recibidos 
        coincidan con los que soporta la implementación de Quaresma.
        """
        self.p = params
        self.d = int(params.d)
        self.N = int(params.N)
        self.q = int(params.q)
        self.elem_bytes = int(getattr(params, "elem_bytes", 27))
        self.key_bytes = int(getattr(params, "key_bytes", 32))

        self.ffi = PswooshFFIClient()
        self._validate_params()

        # None = agnóstico, aún no especializado respecto a peer
        self.active_role: Optional[bool] = None

        self._last_A_bundle: Optional[RustABundle] = None
        self._last_key_bundle: Optional[RustKeyBundle] = None

    def _validate_params(self) -> None:
        """
        Comprueba que los parámetros del backend coinciden con los que
        exige la implementación expuesta por pswoosh_ffi.
        """
        errors = []

        if self.d != self.EXPECTED_D:
            errors.append(f"d={self.d} no coincide con Quaresma (esperado {self.EXPECTED_D})")

        if self.N != self.EXPECTED_N:
            errors.append(f"N={self.N} no coincide con Quaresma (esperado {self.EXPECTED_N})")

        if self.q != self.EXPECTED_Q:
            errors.append(f"q={self.q} no coincide con Quaresma (esperado {self.EXPECTED_Q})")

        if self.key_bytes != self.EXPECTED_KEY_BYTES:
            errors.append(
                f"key_bytes={self.key_bytes} no coincide con Quaresma "
                f"(esperado {self.EXPECTED_KEY_BYTES})"
            )

        if self.ffi.symbytes != 32:
            errors.append(f"pswoosh_ffi expone SYMBYTES={self.ffi.symbytes}, se esperaba 32")

        if self.ffi.publickey_bytes <= 0:
            errors.append("pswoosh_ffi expone PUBLICKEY_BYTES no válido")

        if self.ffi.secretkey_bytes <= 0:
            errors.append("pswoosh_ffi expone SECRETKEY_BYTES no válido")

        if errors:
            raise QuaresmaParameterMismatchError(
                "BackendRust recibió parámetros incompatibles con pswoosh:\n- "
                + "\n- ".join(errors)
            )

    # ------------------------------------------------------------
    # Gestión de rol activo / Cardinalidad
    # ------------------------------------------------------------
    def set_role(self, f: Optional[bool]) -> None:
        """
        Fija el rol/cardinalidad activa del backend para el intercambio actual.
        """
        self.active_role = f

    def get_role(self) -> Optional[bool]:
        """
        Devuelve el rol/cardinalidad actualmente activa.
        """
        return self.active_role

    def _effective_role_for_serialization(self) -> bool:
        """
        Determina qué rol utilizar al serializar claves si no hay uno activo.
        """
        if self.active_role is None:
            return self.DEFAULT_SERIALIZATION_ROLE
        return self.active_role

    def _require_active_role(self) -> bool:
        """
        Exige que exista un rol activo antes de operaciones que dependen
        de una cardinalidad concreta, como la derivación de la shared key.
        """
        if self.active_role is None:
            raise QuaresmaParameterMismatchError(
                "BackendRust necesita un rol activo para derivar la shared key, "
                "pero active_role es None."
            )
        return self.active_role

    # ------------------------------------------------------------
    # Auxiliar
    # ------------------------------------------------------------
    def _require_a_bundle(self, A: Any) -> RustABundle:
        """
        Verifica que la estructura A recibida sea un RustABundle válido.
        """
        if not isinstance(A, RustABundle):
            raise TypeError("BackendRust esperaba un RustABundle en setup/keygen.")
        return A

    def _require_key_bundle(self, obj: Any) -> RustKeyBundle:
        """
        Verifica que el objeto de claves recibido sea un RustKeyBundle válido.
        """
        if not isinstance(obj, RustKeyBundle):
            raise TypeError("BackendRust esperaba un RustKeyBundle para pk/sk.")
        return obj

    # ------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------
    def setup_A(self, seed_A: bytes) -> RustABundle:
        """
        Construye la estructura pública A a partir de la semilla pública.
        Si el rol aún no está fijado, genera ambas cardinalidades posibles
        y las conserva en un bundle. Si ya existe un rol activo, genera
        únicamente la orientación correspondiente.
        """
        if len(seed_A) != self.ffi.symbytes:
            raise QuaresmaParameterMismatchError(
                f"seed_A debe tener {self.ffi.symbytes} bytes para Quaresma, "
                f"pero recibió {len(seed_A)}"
            )

        # Si el rol no está fijado, generamos ambas cardinalidades
        if self.active_role is None:
            a_true = self.ffi.setup_a(seed_A, True)
            a_false = self.ffi.setup_a(seed_A, False)

            bundle = RustABundle({
                True: a_true,
                False: a_false,
            })
        else:
            # Generamos solo la cardinalidad activa
            a = self.ffi.setup_a(seed_A, self.active_role)
            bundle = RustABundle({
                self.active_role: a,
            })

        self._last_A_bundle = bundle
        return bundle

    def keygen(self, A: RustABundle) -> Tuple[RustKeyBundle, RustKeyBundle]:
        """
        Genera el material criptográfico del backend nativo.
        Si el rol no está fijado, produce claves para ambas cardinalidades;
        en caso contrario, genera únicamente el par asociado al rol activo.
        """
        A_bundle = self._require_a_bundle(A)

        if self.active_role is None:
            # Generar ambas cardinalidades
            sk_true, pk_true = self.ffi.keygen(A_bundle.by_role[True], True)
            sk_false, pk_false = self.ffi.keygen(A_bundle.by_role[False], False)

            bundle = RustKeyBundle(
                sk_by_role={
                    True: bytes(sk_true),
                    False: bytes(sk_false),
                },
                pk_by_role={
                    True: bytes(pk_true),
                    False: bytes(pk_false),
                }
            )
        else:
            # Generar solo una cardinalidad
            role = self.active_role
            sk, pk = self.ffi.keygen(A_bundle.by_role[role], role)

            bundle = RustKeyBundle(
                sk_by_role={role: bytes(sk)},
                pk_by_role={role: bytes(pk)},
            )

        self._last_key_bundle = bundle
        return bundle, bundle

    # ------------------------------------------------------------
    # Serialización
    # ------------------------------------------------------------
    def serialize_sk(self, sk: RustKeyBundle | bytes) -> bytes:
        """
        Serializa la clave secreta asociada al rol activo.
        """
        if isinstance(sk, (bytes, bytearray)):
            return bytes(sk)

        bundle = self._require_key_bundle(sk)
        role = self._effective_role_for_serialization()

        if role not in bundle.sk_by_role:
            # Si por alguna razón el bundle solo tiene la otra cardinalidad,
            # usamos la única disponible.
            return next(iter(bundle.sk_by_role.values()))

        return bundle.sk_by_role[role]

    def deserialize_sk(self, buf: bytes) -> bytes:
        """
        Reconstruye una clave secreta desde bytes.
        """
        return bytes(buf)

    def serialize_pk(self, pk: RustKeyBundle | bytes) -> bytes:
        """
        Serializa la clave pública asociada al rol activo.
        """
        if isinstance(pk, (bytes, bytearray)):
            return bytes(pk)

        bundle = self._require_key_bundle(pk)
        role = self._effective_role_for_serialization()

        if role not in bundle.pk_by_role:
            return next(iter(bundle.pk_by_role.values()))

        return bundle.pk_by_role[role]

    def deserialize_pk(self, buf: bytes) -> bytes:
        """
        Reconstruye una clave pública desde bytes.
        """
        return bytes(buf)

    def derive_shared_key(self, my_sk, my_pk, peer_pk) -> bytes:
        """
        Deriva la shared key utilizando directamente la implementación nativa.
        """
        role = self._require_active_role()
        return self.ffi.shared_key(my_sk, my_pk, peer_pk, role)

    # ------------------------------------------------------------
    # Funciones del backend común NO expuestas aquí
    # ------------------------------------------------------------
    def add_rq(self, a, b):
        raise NotImplementedError(
            "BackendRust no expone add_rq en Python"
        )

    def mul_rq(self, a, b):
        raise NotImplementedError(
            "BackendRust no expone mul_rq en Python"
        )

    def offset_poly(self, label: bytes, pk1: bytes, pk2: bytes):
        raise NotImplementedError(
            "BackendRust no usa offset_poly en Python"
        )

    def kprime(self, peer_pk, my_sk, r):
        raise NotImplementedError(
            "BackendRust no usa kprime en Python"
        )

    def cardinality_by_bytes(self, my_public, pk_peer_bytes):
        raise NotImplementedError(
            "BackendRust no usa cardinality_by_bytes en Python"
        )

    def reconcile(self, kv_poly):
        raise NotImplementedError(
            "BackendRust no usa reconcile en Python"
        )