import secrets


def mod_exp(val: int, exp: int, modulus: int) -> int:
    """
    Calcula una exponenciación modular segura usando la primitiva nativa de Python.
    """
    return pow(int(val), int(exp), int(modulus))


def mod_inv(val: int, modulus: int) -> int:
    """
    Calcula la inversa modular de val asumiendo que modulus es primo.
    """
    return mod_exp(val, modulus - 2, modulus)


def root_of_unity_pow2(
    order: int,
    modulus: int,
    *,
    max_tries: int = 256,
) -> int:
    """
    Devuelve una raíz de unidad de orden exactamente order, asumiendo que:
    - modulus es primo;
    - order es una potencia de dos;
    - order divide a modulus-1.
    En el caso negacíclico con order = 2d, basta comprobar que:
        w^(order / 2) == -1 (mod modulus)
    """
    if (order & (order - 1)) != 0:
        raise ValueError(
            "root_of_unity_pow2: 'order' debe ser una potencia de 2."
        )

    if (modulus - 1) % order != 0:
        raise ValueError(
            "root_of_unity_pow2: se requiere que order divida a (modulus - 1)."
        )

    half = order >> 1
    exp = (modulus - 1) // order
    minus_one = modulus - 1

    for _ in range(max_tries):
        a = secrets.randbelow(modulus - 3) + 2  # intervalo [2, modulus - 2]
        w = pow(a, exp, modulus)

        if w == 1:
            continue

        # Para orden potencia de dos, esta condición basta para asegurar
        # que w tiene el orden deseado en el caso negacíclico.
        if pow(w, half, modulus) == minus_one:
            return w

    raise RuntimeError(
        "root_of_unity_pow2: no se encontró una raíz válida en los intentos dados."
    )
