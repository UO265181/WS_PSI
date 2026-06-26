# Crypto/helpers/swoosh/params.py
from dataclasses import dataclass, replace
from flint import fmpz

@dataclass(frozen=True)
class SwooshParameters:
    """
    Parámetros nominales del esquema, semillas y etiquetas:
      - d = 256
      - q = 2^214 - 255 (para py-NTT se elige el primo compatible más cercano)
      - N = 32
      - anillo: Z_q[X] / (X^d + 1)
    """
    d: int = 256
    q: object = fmpz(2) ** 214 - 255
    q_ntt: object = fmpz("26328072917139296674479506920917608079723773850137277813577701889")

    N: int = 32
    seed_A: bytes = b"TFG-SWOOSH-SEED-A-00000000000000"

    # Dominios
    domain_base: bytes = b"Swoosh"
    domain_A: bytes = b"Swoosh|A"
    domain_sk: bytes = b"Swoosh|sk"
    domain_e: bytes = b"Swoosh|e"
    domain_offset: bytes = b"Swoosh|offset"

    elem_bytes: int = 27   # 216 bits, suficiente para q de 214 bits
    key_bytes: int = 32    # Tamaño de shared key


    def with_N(self, N: int) -> "SwooshParameters":
        return replace(self, N=N)

    def with_seed_A(self, seed_A: bytes) -> "SwooshParameters":
        return replace(self, seed_A=seed_A)

    def with_q(self, q) -> "SwooshParameters":
        return replace(self, q=q)

    def with_q_ntt(self, q_ntt) -> "SwooshParameters":
        return replace(self, q_ntt=q_ntt)
