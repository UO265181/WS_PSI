from math import log2
from typing import List, Sequence, TypeVar

T = TypeVar("T")


def reverse_bits(value: int, width: int) -> int:
    """
    Invierte los bits de value considerando una anchura fija width.
    """
    binary_val = f"{value:0{width}b}"
    return int(binary_val[::-1], 2)


def bit_reverse_vec(values: Sequence[T]) -> List[T]:
    """
    Reordena una secuencia según el índice obtenido por inversión de bits.
    La longitud de la secuencia debe ser una potencia de dos.
    """
    result = [None] * len(values)
    width = int(log2(len(values)))
    for i in range(len(values)):
        result[i] = values[reverse_bits(i, width)]
    return result