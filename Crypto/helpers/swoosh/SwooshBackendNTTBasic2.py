from __future__ import annotations

import secrets
from typing import List, Tuple, Union

from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackendNTTBasic import (
    BackendNTTBasic,
    PolyNTT,
    Poly,
    Vec,
    Mat,
    Sk,
    Pk,
)


HatPoly = List[int]
HatVec = List[HatPoly]
HatMat = List[List[HatPoly]]


class BackendNTTBasic2(BackendNTTBasic):
    """
    Variante optimizada de BackendNTTBasic.

    La mejora principal consiste en evitar transformadas redundantes durante
    los productos matriz-vector, vector-matriz y productos escalares. En lugar
    de llamar repetidamente a mul_rq(), que aplica FTT directa, producto punto
    a punto e inversa en cada multiplicación, esta versión acumula los productos
    directamente en el dominio transformado y aplica la inversa solo al resultado
    final de cada componente.
    """

    def __init__(self, params: SwooshParameters):
        super().__init__(params)

    # ------------------------------------------------------------
    # Utilidades en dominio NTT
    # ------------------------------------------------------------
    def _fwd_poly(self, p: PolyNTT) -> HatPoly:
        """
        Transformada directa de un polinomio al dominio NTT.
        """
        return self.ntt_ctx.ftt_fwd(p._c)

    def _inv_poly(self, p_hat: HatPoly) -> PolyNTT:
        """
        Transformada inversa desde dominio NTT y materialización como PolyNTT.
        """
        return PolyNTT(self.ntt_ctx.ftt_inv(p_hat))

    def _vec_hat(self, v: Vec) -> HatVec:
        """
        Transforma un vector de polinomios al dominio NTT.
        """
        return [self._fwd_poly(p) for p in v]

    def _mat_hat(self, A: Mat) -> HatMat:
        """
        Transforma una matriz de polinomios al dominio NTT.
        """
        return [
            [self._fwd_poly(A[i][j]) for j in range(self.N)]
            for i in range(self.N)
        ]

    def _zero_hat(self) -> HatPoly:
        """
        Devuelve un polinomio nulo en dominio NTT.
        """
        return [0] * self.d

    def _pointwise_mul_add(
        self,
        acc_hat: HatPoly,
        a_hat: HatPoly,
        b_hat: HatPoly,
    ) -> None:
        """
        Acumula en acc_hat el producto punto a punto a_hat * b_hat.

        Esta función modifica acc_hat in-place para evitar crear objetos
        intermedios en cada producto.
        """
        q = self.q
        d = self.d

        for i in range(d):
            acc_hat[i] = (acc_hat[i] + a_hat[i] * b_hat[i]) % q

    # ------------------------------------------------------------
    # Productos optimizados en dominio NTT
    # ------------------------------------------------------------
    def _matvec_hat(self, A_hat: HatMat, v_hat: HatVec) -> Vec:
        """
        Calcula A · v acumulando en dominio NTT.

        En lugar de realizar una transformada inversa por cada producto
        polinómico, se acumula cada componente en el dominio transformado
        y se aplica una única transformada inversa al final.
        """
        out: Vec = []

        for i in range(self.N):
            acc_hat = self._zero_hat()

            for j in range(self.N):
                self._pointwise_mul_add(
                    acc_hat=acc_hat,
                    a_hat=A_hat[i][j],
                    b_hat=v_hat[j],
                )

            out.append(self._inv_poly(acc_hat))

        return out

    def _vecmat_hat(self, s_hat: HatVec, A_hat: HatMat) -> Vec:
        """
        Calcula s^T · A acumulando en dominio NTT.
        """
        out: Vec = []

        for j in range(self.N):
            acc_hat = self._zero_hat()

            for i in range(self.N):
                self._pointwise_mul_add(
                    acc_hat=acc_hat,
                    a_hat=s_hat[i],
                    b_hat=A_hat[i][j],
                )

            out.append(self._inv_poly(acc_hat))

        return out

    def _dot_hat(self, u_hat: HatVec, v_hat: HatVec) -> PolyNTT:
        """
        Calcula el producto escalar de dos vectores de polinomios acumulando
        directamente en dominio NTT.
        """
        acc_hat = self._zero_hat()

        for i in range(self.N):
            self._pointwise_mul_add(
                acc_hat=acc_hat,
                a_hat=u_hat[i],
                b_hat=v_hat[i],
            )

        return self._inv_poly(acc_hat)

    # ------------------------------------------------------------
    # Keygen optimizado
    # ------------------------------------------------------------
    def keygen(self, A: Union[PolyNTT, Mat]) -> Tuple[Sk, Pk]:
        """
        Genera la clave secreta y la clave pública.

        Para N > 1 se optimiza el cálculo de pkL y pkR:
          - se transforma A una sola vez;
          - se transforman skL y skR una sola vez;
          - se acumulan productos en dominio NTT;
          - se aplica FTT inversa solo al final de cada componente.
        """
        noiseseed = secrets.token_bytes(32)

        if self.N == 1:
            return super().keygen(A)

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

        A_hat = self._mat_hat(A)
        skL_hat = self._vec_hat(skL)
        skR_hat = self._vec_hat(skR)

        pkL_vec = self._vecmat_hat(skL_hat, A_hat)
        pkR_vec = self._matvec_hat(A_hat, skR_hat)

        pkL = [self.add_rq(pkL_vec[i], eL[i]) for i in range(self.N)]
        pkR = [self.add_rq(pkR_vec[i], eR[i]) for i in range(self.N)]

        return (skL, skR), (pkL, pkR)

    # ------------------------------------------------------------
    # k' optimizado
    # ------------------------------------------------------------
    def kprime(self, peer_pk: Pk, my_sk: Sk, r: PolyNTT) -> PolyNTT:
        """
        Calcula k' antes de reconciliación.

        Para N > 1 se optimizan los dos productos escalares usando acumulación
        en dominio NTT.
        """
        pkL_peer, pkR_peer = peer_pk
        skL_me, skR_me = my_sk

        if self.N == 1:
            return super().kprime(peer_pk, my_sk, r)

        skL_hat = self._vec_hat(skL_me)
        skR_hat = self._vec_hat(skR_me)
        pkL_hat = self._vec_hat(pkL_peer)
        pkR_hat = self._vec_hat(pkR_peer)

        term1 = self._dot_hat(skL_hat, pkR_hat)
        term2 = self._dot_hat(pkL_hat, skR_hat)

        return self.add_rq(self.add_rq(term1, term2), r)