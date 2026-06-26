from __future__ import annotations
import secrets
from typing import Any, List, Tuple, Union
from flint import fmpz_mod_poly_ctx
from .params import SwooshParameters
from .SwooshBackend import SwooshBackend

Poly = Any  # Polinomio de FLINT
Vec = List[Poly]
Mat = List[List[Poly]]

Sk = Tuple[Union[Poly, Vec], Union[Poly, Vec]]  # (sk_L, sk_R)
Pk = Tuple[Union[Poly, Vec], Union[Poly, Vec]]  # (pk_L, pk_R)


class BackendFlint(SwooshBackend):
    """
    Backend algebraico basado en python-flint.

    Utiliza FLINT para representar polinomios módulo q y delega en Python
    la construcción de A, el muestreo de ruido, la serialización 
    y la derivación de la shared key.
    """

    def __init__(self, params: SwooshParameters):
        """
        Inicializa el backend con los parámetros del esquema.
        Prepara el contexto polinómico de FLINT y calcula las constantes
        auxiliares necesarias para el rejection sampling.
        """
        self.p = params
        self.d = int(params.d)
        self.N = int(params.N)
        self.q = int(params.q)
        self.elem_bytes = int(getattr(params, "elem_bytes", 27))

        self.R = fmpz_mod_poly_ctx(self.q)

        # rejection sampling: candidatos uniformes en [0, 2^(8*elem_bytes))
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
        eta: int
        ) -> Poly:
        """
        Genera un polinomio con distribución CBD a partir de una semilla y un nonce.
        Se utiliza para muestrear tanto secretos como errores del protocolo.
        """
        coeffs = self.sample_cbd_coeffs(label=label, seed=seed, nonce=nonce, eta=eta)
        return self.R(coeffs)

    # ------------------------------------------------------------------
    # Vectores y matrices sobre R_q = Z_q[x]/(x^d + 1)
    # ------------------------------------------------------------------
    def _reduce_mod_xd1(self, p: Poly) -> Poly:
        """
        Reduce un polinomio módulo x^d + 1 mediante plegado negacíclico.
        Dado que FLINT trabaja naturalmente en Z_q[x], esta reducción ajusta
        el resultado al anillo cociente R_q utilizado por SWOOSH.
        """
        coeffs = list(p.coeffs())
        if len(coeffs) < 2 * self.d:
            coeffs += [0] * (2 * self.d - len(coeffs))
        out = [0] * self.d
        for i in range(self.d):
            out[i] = (int(coeffs[i]) - int(coeffs[i + self.d])) % self.q
        return self.R(out)

    def mul_rq(self, a: Poly, b: Poly) -> Poly:
        """
        Multiplica dos polinomios y reduce el resultado en R_q.
        """
        return self._reduce_mod_xd1(a * b)

    def add_rq(self, a: Poly, b: Poly) -> Poly:
        """
        Suma dos polinomios y reduce el resultado en R_q.
        """
        return self._reduce_mod_xd1(a + b)

    def _zero_poly(self) -> Poly:
        """
        Devuelve el polinomio nulo del anillo.
        """
        return self.R.zero()

    def _zero_vec(self) -> Vec:
        """
        Construye un vector nulo de longitud N sobre R_q.
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

    def _dot(self, u: Vec, v: Vec) -> Poly:
        """
        Calcula el producto escalar de dos vectores de polinomios en R_q.
        """
        acc = self._zero_poly()
        for i in range(self.N):
            acc = self.add_rq(acc, self.mul_rq(u[i], v[i]))
        return acc

    # ------------------------------------------------------------------
    # Serialización
    # ------------------------------------------------------------------
    def poly_to_bytes(self, p: Poly) -> bytes:
        """
        Serializa un polinomio a bytes.
        """
        coeffs = list(p.coeffs())
        if len(coeffs) < self.d:
            coeffs += [0] * (self.d - len(coeffs))
        out = bytearray(self.d * self.elem_bytes)
        for i in range(self.d):
            c = int(coeffs[i]) % self.q
            out[i * self.elem_bytes:(i + 1) * self.elem_bytes] = c.to_bytes(
                self.elem_bytes, "little"
            )
        return bytes(out)

    def poly_from_bytes(self, buf: bytes) -> Poly:
        """
        Reconstruye un polinomio a partir de su representación en bytes.
        """
        expected = self.d * self.elem_bytes
        if len(buf) != expected:
            raise ValueError(
                f"Longitud inválida: esperaba {expected} bytes y recibí {len(buf)}"
            )
        coeffs = []
        for i in range(self.d):
            chunk = buf[i * self.elem_bytes:(i + 1) * self.elem_bytes]
            coeffs.append(int.from_bytes(chunk, "little") % self.q)
        return self.R(coeffs)

    def _vec_to_bytes(self, v: Vec) -> bytes:
        """
        Serializa un vector de polinomios concatenando cada uno de sus elementos.
        """
        return b"".join(self.poly_to_bytes(p) for p in v)

    def _vec_from_bytes(self, buf: bytes) -> Vec:
        """
        Reconstruye un vector de polinomios a partir de su representación en bytes.
        """
        poly_bytes = self.d * self.elem_bytes
        expected = self.N * poly_bytes
        if len(buf) != expected:
            raise ValueError(
                f"Longitud inválida de vector: esperaba {expected} y recibí {len(buf)}"
            )
        return [
            self.poly_from_bytes(buf[i * poly_bytes:(i + 1) * poly_bytes])
            for i in range(self.N)
        ]

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

    # ------------------------------------------------------------------
    # L||R bytes helpers
    # ------------------------------------------------------------------
    def split_lr_bytes(self, buf: bytes) -> Tuple[bytes, bytes]:
        """
        Divide una representación L||R en sus dos mitades izquierda y derecha.
        """
        poly_bytes = self.d * self.elem_bytes
        side_bytes = poly_bytes if self.N == 1 else self.N * poly_bytes
        if len(buf) != 2 * side_bytes:
            raise ValueError(
                f"Longitud inválida: esperaba {2 * side_bytes} y recibí {len(buf)}"
            )
        return buf[:side_bytes], buf[side_bytes:]

    def join_lr_bytes(self, left: bytes, right: bytes) -> bytes:
        """
        Une las mitades izquierda y derecha en una única representación binaria.
        """
        return left + right

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def setup_A(self, seed_A: bytes) -> Union[Poly, Mat]:
        """
        Construye la estructura pública A a partir de la semilla pública.
        Para N = 1 devuelve un polinomio; para N > 1 construye una matriz
        N x N de polinomios mediante SHAKE y rejection sampling.
        """
        # N == 1: un único polinomio
        if self.N == 1:
            coeffs: List[int] = []
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
            return self.R(coeffs)

        # N > 1: matriz N x N
        A: Mat = [[self._zero_poly() for _ in range(self.N)] for _ in range(self.N)]
        ctr = 0
        for i in range(self.N):
            for j in range(self.N):
                coeffs: List[int] = []
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
                A[i][j] = self.R(coeffs)
        return A



    def keygen(self, A: Union[Poly, Mat]) -> Tuple[Sk, Pk]:
        """
        Genera la clave secreta y la clave pública del esquema.
        """
        noiseseed = secrets.token_bytes(32)

        if self.N == 1:
            skL = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=0, eta=1)
            skR = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=1, eta=1)
            eL = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=2, eta=1)
            eR = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=3, eta=1)
            pkL = self.add_rq(self.mul_rq(A, skL), eL)
            pkR = self.add_rq(self.mul_rq(A, skR), eR)
            return (skL, skR), (pkL, pkR)

        # N > 1: vectores de N polinomios
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
        pkL_vec = self._vecmat(skL, A)
        pkR_vec = self._matvec(A, skR)
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

    def offset_poly(self, label: bytes, pk1: bytes, pk2: bytes) -> Poly:
        """
        Construye el polinomio de offset r a partir de las claves públicas ordenadas.
        La generación se realiza mediante SHAKE y rejection sampling.
        """
        rin = pk1 + pk2
        coeffs: List[int] = []
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
        return self.R(coeffs)

    def kprime(self, peer_pk: Pk, my_sk: Sk, r: Poly) -> Poly:
        """
        Calcula el valor preliminar k' antes de la reconciliación final.
        """
        pkL_peer, pkR_peer = peer_pk
        skL_me, skR_me = my_sk
        if self.N == 1:
            term1 = self.mul_rq(skL_me, pkR_peer)      # sL_me * pkR_peer
            term2 = self.mul_rq(pkL_peer, skR_me)      # pkL_peer * sR_me
            return self.add_rq(self.add_rq(term1, term2), r)

        # N > 1: productos escalares en R_q
        term1 = self._dot(skL_me, pkR_peer)            # sL_me^T · pkR_peer
        term2 = self._dot(pkL_peer, skR_me)            # pkL_peer · sR_me
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