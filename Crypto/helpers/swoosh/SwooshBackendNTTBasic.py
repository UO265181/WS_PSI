from __future__ import annotations

import hashlib
import secrets
from typing import Any, List, Tuple, Union

from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackend import SwooshBackend
from Crypto.helpers.swoosh.ntt_utils.ntt_context import NTTContext

Poly = Any # Polinomio del backend NTT.
Vec = List[Poly]
Mat = List[List[Poly]]

Sk = Tuple[Union[Poly, Vec], Union[Poly, Vec]]
Pk = Tuple[Union[Poly, Vec], Union[Poly, Vec]]


class PolyNTT:
    """
    Representación mínima de un polinomio para el backend.
    Internamente almacena la lista de coeficientes en el dominio habitual
    de coeficientes, no en el dominio transformado.
    """

    __slots__ = ("_c",)

    def __init__(self, coeffs: List[int]):
        """
        Inicializa el polinomio a partir de una lista de coeficientes.
        """
        self._c = coeffs

    def coeffs(self) -> List[int]:
        """
        Devuelve una copia de los coeficientes del polinomio.
        """
        return list(self._c)

    def __eq__(self, other: object) -> bool:
        """
        Compara dos polinomios por igualdad de coeficientes.
        """
        if not isinstance(other, PolyNTT):
            return NotImplemented
        return self._c == other._c

    def __repr__(self) -> str:
        """
        Devuelve una representación abreviada del polinomio.
        """
        if not self._c:
            return "PolyNTT([])"
        h = hashlib.sha256(
            b"".join(
                int(x).to_bytes(4, "little", signed=False)
                for x in self._c[:32]
            )
        ).hexdigest()[:12]
        return f"PolyNTT(d={len(self._c)}, fp={h})"


class BackendNTTBasic(SwooshBackend):
    """
    Backend NTT/FTT para el anillo R_q = Z_q[x] / (x^d + 1),
    con d potencia de 2.
    """

    def __init__(self, params: SwooshParameters):
        """
        Inicializa el backend y construye el contexto NTT asociado.
        Valida que el módulo elegido sea compatible con la
        condición negacíclica necesaria para la transformada.
        """
        self.p = params
        self.d = int(params.d)
        self.N = int(params.N)
        self.q = int(params.q_ntt)
        self.elem_bytes = int(
            getattr(params, "elem_bytes", (self.q.bit_length() + 7) // 8)
        )

        # Condición NTT negacíclica: 2d | (q - 1)
        if (self.q - 1) % (2 * self.d) != 0:
            raise ValueError(
                "NTTBasicBackend: se requiere q ≡ 1 (mod 2d) "
                "para FTT/NTT negacíclica."
            )

        self.ntt_ctx = NTTContext(
            poly_degree=self.d,
            coeff_modulus=self.q,
        )

        # rejection sampling para uniformes
        k = 8 * self.elem_bytes
        self.M = 1 << k
        self.T = self.M - (self.M % self.q)

    # ------------------------------------------------------------------
    # Auxiliar
    # ------------------------------------------------------------------
    def sample_cbd_poly(
        self,
        label: bytes,
        seed: bytes,
        nonce: int,
        eta: int,
    ) -> PolyNTT:
        """
        Genera un polinomio con distribución CBD a partir de una semilla.
        Se utiliza para muestrear tanto secretos como errores del protocolo.
        """
        coeffs = self.sample_cbd_coeffs(label=label, seed=seed, nonce=nonce, eta=eta)
        return PolyNTT(coeffs)

    # ------------------------------------------------------------
    # Operaciones en R_q
    # ------------------------------------------------------------
    def add_rq(self, a: PolyNTT, b: PolyNTT) -> PolyNTT:
        """
        Suma dos polinomios en R_q coeficiente a coeficiente.
        """
        return PolyNTT(
            [(a._c[i] + b._c[i]) % self.q for i in range(self.d)]
        )

    def mul_rq(self, a: PolyNTT, b: PolyNTT) -> PolyNTT:
        """
        Multiplica dos polinomios mediante FTT/NTT negacíclica.
        """
        A = self.ntt_ctx.ftt_fwd(a._c)
        B = self.ntt_ctx.ftt_fwd(b._c)
        C = [(A[i] * B[i]) % self.q for i in range(self.d)]
        c = self.ntt_ctx.ftt_inv(C)
        return PolyNTT(c)

    def _zero_poly(self) -> PolyNTT:
        """
        Devuelve el polinomio nulo del anillo.
        """
        return PolyNTT([0] * self.d)

    def _zero_vec(self) -> Vec:
        """
        Construye un vector nulo de longitud N.
        """
        return [self._zero_poly() for _ in range(self.N)]

    def _matvec(self, A: Mat, v: Vec) -> Vec:
        """
        Calcula el producto matriz-vector A · v en el caso N > 1.
        """
        out = self._zero_vec()
        for i in range(self.N):
            acc = self._zero_poly()
            for j in range(self.N):
                acc = self.add_rq(acc, self.mul_rq(A[i][j], v[j]))
            out[i] = acc
        return out

    def _vecmat(self, s: Vec, A: Mat) -> Vec:
        """
        Calcula el producto vector-matriz s^T · A en el caso N > 1.
        """
        out = self._zero_vec()
        for j in range(self.N):
            acc = self._zero_poly()
            for i in range(self.N):
                acc = self.add_rq(acc, self.mul_rq(s[i], A[i][j]))
            out[j] = acc
        return out

    def _dot(self, u: Vec, v: Vec) -> PolyNTT:
        """
        Calcula el producto escalar de dos vectores de polinomios en R_q.
        """
        acc = self._zero_poly()
        for i in range(self.N):
            acc = self.add_rq(acc, self.mul_rq(u[i], v[i]))
        return acc

    # ------------------------------------------------------------
    # Serialización 
    # ------------------------------------------------------------
    def poly_to_bytes(self, p: PolyNTT) -> bytes:
        """
        Serializa un polinomio a bytes en formato little-endian.
        """
        out = bytearray(self.d * self.elem_bytes)
        for i in range(self.d):
            out[
                i * self.elem_bytes:(i + 1) * self.elem_bytes
            ] = int(p._c[i]).to_bytes(self.elem_bytes, "little")
        return bytes(out)

    def poly_from_bytes(self, buf: bytes) -> PolyNTT:
        """
        Reconstruye un polinomio a partir de su representación en bytes.
        """
        expected = self.d * self.elem_bytes
        if len(buf) != expected:
            raise ValueError(
                f"poly_from_bytes: esperaba {expected} bytes y recibió {len(buf)}"
            )

        coeffs = []
        for i in range(self.d):
            chunk = buf[i * self.elem_bytes:(i + 1) * self.elem_bytes]
            coeffs.append(int.from_bytes(chunk, "little") % self.q)

        return PolyNTT(coeffs)

    def _vec_to_bytes(self, v: Vec) -> bytes:
        """
        Serializa un vector de polinomios concatenando sus elementos.
        """
        return b"".join(self.poly_to_bytes(p) for p in v)

    def _vec_from_bytes(self, buf: bytes) -> Vec:
        """
        Reconstruye un vector de polinomios a partir de bytes.
        """
        poly_bytes = self.d * self.elem_bytes
        expected = self.N * poly_bytes

        if len(buf) != expected:
            raise ValueError(
                f"_vec_from_bytes: esperaba {expected} bytes y recibió {len(buf)}"
            )

        return [
            self.poly_from_bytes(buf[i * poly_bytes:(i + 1) * poly_bytes])
            for i in range(self.N)
        ]

    def split_lr_bytes(self, buf: bytes) -> Tuple[bytes, bytes]:
        """
        Divide una representación L||R en sus mitades izquierda y derecha.
        """
        poly_bytes = self.d * self.elem_bytes
        side_bytes = poly_bytes if self.N == 1 else self.N * poly_bytes

        if len(buf) != 2 * side_bytes:
            raise ValueError(
                f"split_lr_bytes: esperaba {2 * side_bytes} bytes y recibió {len(buf)}"
            )

        return buf[:side_bytes], buf[side_bytes:]

    def join_lr_bytes(self, left: bytes, right: bytes) -> bytes:
        """
        Une las mitades izquierda y derecha en una sola secuencia binaria.
        """
        return left + right

    def serialize_sk(self, sk: Sk) -> bytes:
        """
        Serializa la clave secreta del backend en formato L||R.
        """
        skL, skR = sk
        left = self.poly_to_bytes(skL) if self.N == 1 else self._vec_to_bytes(skL)
        right = self.poly_to_bytes(skR) if self.N == 1 else self._vec_to_bytes(skR)
        return self.join_lr_bytes(left, right)

    def deserialize_sk(self, buf: bytes) -> Sk:
        """
        Reconstruye la clave secreta a partir de su representación serializada.
        """
        Lb, Rb = self.split_lr_bytes(buf)
        left = self.poly_from_bytes(Lb) if self.N == 1 else self._vec_from_bytes(Lb)
        right = self.poly_from_bytes(Rb) if self.N == 1 else self._vec_from_bytes(Rb)
        return (left, right)

    def serialize_pk(self, pk: Pk) -> bytes:
        """
        Serializa la clave pública del backend en formato L||R.
        """
        pkL, pkR = pk
        left = self.poly_to_bytes(pkL) if self.N == 1 else self._vec_to_bytes(pkL)
        right = self.poly_to_bytes(pkR) if self.N == 1 else self._vec_to_bytes(pkR)
        return self.join_lr_bytes(left, right)

    def deserialize_pk(self, buf: bytes) -> Pk:
        """
        Reconstruye la clave pública a partir de su representación serializada.
        """
        Lb, Rb = self.split_lr_bytes(buf)
        left = self.poly_from_bytes(Lb) if self.N == 1 else self._vec_from_bytes(Lb)
        right = self.poly_from_bytes(Rb) if self.N == 1 else self._vec_from_bytes(Rb)
        return (left, right)

    # ------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------
    def setup_A(self, seed_A: bytes) -> Union[PolyNTT, Mat]:
        """
        Construye la estructura pública A a partir de la semilla pública.
        Para N=1 devuelve un polinomio; para N>1 construye una matriz
        N x N de polinomios compatible con el backend NTT.
        """
        if self.N == 1:
            coeffs = []
            ctr = 0
            while len(coeffs) < self.d:
                block = self._shake(
                    self.p.domain_base,
                    self.p.domain_A,
                    seed_A,
                    ctr.to_bytes(4, "little"),
                    outlen=self.elem_bytes,
                )
                ctr += 1
                u = int.from_bytes(block, "little")
                if u < self.T:
                    coeffs.append(u % self.q)
            return PolyNTT(coeffs)

        A: Mat = [[self._zero_poly() for _ in range(self.N)] for _ in range(self.N)]
        ctr = 0
        for i in range(self.N):
            for j in range(self.N):
                coeffs = []
                while len(coeffs) < self.d:
                    block = self._shake(
                        self.p.domain_base,
                        self.p.domain_A,
                        seed_A,
                        i.to_bytes(2, "little"),
                        j.to_bytes(2, "little"),
                        ctr.to_bytes(4, "little"),
                        outlen=self.elem_bytes,
                    )
                    ctr += 1
                    u = int.from_bytes(block, "little")
                    if u < self.T:
                        coeffs.append(u % self.q)
                A[i][j] = PolyNTT(coeffs)
        return A

    def keygen(self, A: Union[PolyNTT, Mat]) -> Tuple[Sk, Pk]:
        """
        Genera la clave secreta y la clave pública.
        """
        noiseseed = secrets.token_bytes(32)

        if self.N == 1:
            skL = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=0, eta=1)
            skR = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=1, eta=1)
            eL = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=2, eta=1)
            eR = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=3, eta=1)

            pkL = self.add_rq(self.mul_rq(skL, A), eL)   # s^T A (trivial N=1)
            pkR = self.add_rq(self.mul_rq(A, skR), eR)   # A s
            return (skL, skR), (pkL, pkR)

        # N > 1 
        skL: Vec = [
            self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=10 + i, eta=1)
            for i in range(self.N)
        ]
        skR: Vec = [
            self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=20 + i, eta=1)
            for i in range(self.N)
        ]
        eL: Vec = [
            self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=30 + i, eta=1)
            for i in range(self.N)
        ]
        eR: Vec = [
            self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=40 + i, eta=1)
            for i in range(self.N)
        ]

        pkL_vec = self._vecmat(skL, A)     # sL^T A
        pkR_vec = self._matvec(A, skR)     # A sR

        pkL = [self.add_rq(pkL_vec[i], eL[i]) for i in range(self.N)]
        pkR = [self.add_rq(pkR_vec[i], eR[i]) for i in range(self.N)]
        return (skL, skR), (pkL, pkR)


    # ------------------------------------------------------------------
    # SdK
    # ------------------------------------------------------------------
    def derive_shared_key(
        self,
        my_sk: bytes,
        my_pk: bytes,
        peer_pk: bytes,
    ) -> bytes:
        """
        Deriva la shared key a partir del material local y de la clave pública del peer.
        1. fijar el orden canónico de claves públicas
        2. construir el offset r
        3. deserializar clave pública y secreta
        4. calcular k'
        5. reconciliar el resultado para obtener la calve compartida
        """
        pk1, pk2 = self.cardinality_by_bytes(my_pk, peer_pk)
        r = self.offset_poly(self.p.domain_offset, pk1, pk2)

        pk_peer = self.deserialize_pk(peer_pk)
        sk_me = self.deserialize_sk(my_sk)

        kprime = self.kprime(pk_peer, sk_me, r)
        self.shared_key = self.reconcile(kprime)
        return self.shared_key

    def offset_poly(self, label: bytes, pk1: bytes, pk2: bytes) -> PolyNTT:
        """
        Construye el polinomio de offset a partir de las claves públicas ordenadas.
        """
        rin = pk1 + pk2
        coeffs = []

        for i in range(self.d):
            ctr = 0
            while True:
                block = self._shake(
                    self.p.domain_base,
                    label,
                    rin,
                    i.to_bytes(4, "little"),
                    ctr.to_bytes(4, "little"),
                    outlen=self.elem_bytes,
                )
                u = int.from_bytes(block, "little")
                if u < self.T:
                    coeffs.append(u % self.q)
                    break
                ctr += 1

        return PolyNTT(coeffs)
    
    def kprime(self, peer_pk: Pk, my_sk: Sk, r: PolyNTT) -> PolyNTT:
        """
        Calcula el valor preliminar k' antes de la reconciliación final.
        """
        pkL_peer, pkR_peer = peer_pk
        skL_me, skR_me = my_sk

        if self.N == 1:
            term1 = self.mul_rq(skL_me, pkR_peer)      # sL * pkR
            term2 = self.mul_rq(pkL_peer, skR_me)      # pkL * sR
            return self.add_rq(self.add_rq(term1, term2), r)

        term1 = self._dot(skL_me, pkR_peer)            # <sL, pkR>
        term2 = self._dot(pkL_peer, skR_me)            # <pkL, sR>
        return self.add_rq(self.add_rq(term1, term2), r)

    def reconcile(self, kv_poly: Poly) -> bytes:
        """
        Reconciliación final de k' para obtener una secuencia binaria.
        Cada coeficiente se proyecta a un bit según su posición relativa
        respecto a los umbrales q/4 y 3q/4.
        """
        coeffs = list(kv_poly.coeffs())
        if len(coeffs) < self.p.d:
            coeffs += [0] * (self.p.d - len(coeffs))

        q = int(self.p.q)
        out = bytearray(self.p.d // 8)

        q4 = q // 4
        tq4 = (3 * q) // 4

        for i in range(self.p.d // 8):
            acc = 0
            for j in range(8):
                c = int(coeffs[8 * i + j]) % q
                bit = 1 if q4 <= c <= tq4 else 0
                acc |= bit << j
            out[i] = acc

        return bytes(out[: self.p.key_bytes])