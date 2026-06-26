from math import log2
from .number_theory import mod_inv, root_of_unity_pow2
from .bit_operations import bit_reverse_vec, reverse_bits


class NTTContext:
    """
    Contexto de la transformada NTT/FTT para polinomios en R_q.
    Encapsula el grado del polinomio, el módulo de coeficientes y las
    precomputaciones necesarias para aplicar la transformada directa
    e inversa sobre el anillo negacíclico correspondiente.
    """

    def __init__(
        self,
        poly_degree: int,
        coeff_modulus: int,
        root_of_unity: int | None = None,
    ):
        """
        Inicializa el contexto NTT con un grado y un módulo dados.
        Si no se proporciona una raíz de unidad, intenta construir una
        automáticamente a partir del módulo y del grado del polinomio.
        """
        if (poly_degree & (poly_degree - 1)) != 0:
            raise ValueError(
                f"Degree debe ser potencia de 2. Se recibió poly_degree={poly_degree}"
            )

        self.coeff_modulus = int(coeff_modulus)
        self.degree = int(poly_degree)

        if root_of_unity is None:
            root_of_unity = root_of_unity_pow2(
                order=2 * self.degree,
                modulus=self.coeff_modulus,
            )

        self.precompute_ntt(root_of_unity)

    def precompute_ntt(self, root_of_unity: int) -> None:
        """
        Precomputa raíces de unidad, raíces inversas y permutaciones por bits.
        Estas estructuras se reutilizan después en la transformada directa
        e inversa para evitar recomputaciones innecesarias.
        """
        self.roots_of_unity = [1] * self.degree
        for i in range(1, self.degree):
            self.roots_of_unity[i] = (
                self.roots_of_unity[i - 1] * root_of_unity
            ) % self.coeff_modulus

        root_of_unity_inv = mod_inv(root_of_unity, self.coeff_modulus)
        self.roots_of_unity_inv = [1] * self.degree
        for i in range(1, self.degree):
            self.roots_of_unity_inv[i] = (
                self.roots_of_unity_inv[i - 1] * root_of_unity_inv
            ) % self.coeff_modulus

        self.reversed_bits = [0] * self.degree
        width = int(log2(self.degree))
        for i in range(self.degree):
            self.reversed_bits[i] = reverse_bits(i, width) % self.degree

    def ntt(self, coeffs, rou):
        """
        Aplica la transformada iterativa sobre una lista de coeficientes.
        El vector `rou` debe contener las raíces de unidad adecuadas para
        la dirección de la transformada que se desea aplicar.
        """
        num_coeffs = len(coeffs)

        if len(rou) != num_coeffs:
            raise ValueError(
                f"rou debe tener longitud {num_coeffs}, pero recibió {len(rou)}"
            )

        result = bit_reverse_vec(coeffs)
        log_num_coeffs = int(log2(num_coeffs))

        for logm in range(1, log_num_coeffs + 1):
            for j in range(0, num_coeffs, (1 << logm)):
                for i in range(1 << (logm - 1)):
                    index_even = j + i
                    index_odd = j + i + (1 << (logm - 1))

                    rou_idx = i << (1 + log_num_coeffs - logm)
                    omega_factor = (
                        rou[rou_idx] * result[index_odd]
                    ) % self.coeff_modulus

                    result[index_even] = (
                        result[index_even] + omega_factor
                    ) % self.coeff_modulus
                    result[index_odd] = (
                        result[index_even] - 2 * omega_factor
                    ) % self.coeff_modulus

        return result

    def ftt_fwd(self, coeffs):
        """
        Aplica la transformada directa FTT a una lista de coeficientes.
        Previamente multiplica por las raíces adecuadas para adaptar la
        transformada al caso negacíclico empleado en el backend.
        """
        num_coeffs = len(coeffs)

        if num_coeffs != self.degree:
            raise ValueError(
                f"ftt_fwd esperaba {self.degree} coeficientes y recibió {num_coeffs}"
            )

        ftt_input = [
            (int(coeffs[i]) * self.roots_of_unity[i]) % self.coeff_modulus
            for i in range(num_coeffs)
        ]
        return self.ntt(ftt_input, self.roots_of_unity)

    def ftt_inv(self, coeffs):
        """
        Aplica la transformada inversa FTT a una lista de coeficientes.
        Tras la transformada inversa, reescala el resultado por el inverso
        del grado del polinomio dentro del módulo actual.
        """
        num_coeffs = len(coeffs)

        if num_coeffs != self.degree:
            raise ValueError(
                f"ftt_inv esperaba {self.degree} coeficientes y recibió {num_coeffs}"
            )

        to_scale_down = self.ntt(coeffs, self.roots_of_unity_inv)
        deg_inv = mod_inv(self.degree, self.coeff_modulus)

        return [
            (int(to_scale_down[i]) * self.roots_of_unity_inv[i] * deg_inv)
            % self.coeff_modulus
            for i in range(num_coeffs)
        ]