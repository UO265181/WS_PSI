import unittest

from Crypto.helpers.swoosh.params import SwooshParameters


class TestSwooshParameters(unittest.TestCase):
    """
    Pruebas unitarias sobre la clase SwooshParameters.
    """

    def test_default_parameters(self):
        """
        Verifica que la configuración por defecto del esquema
        se inicializa con los valores nominales esperados.
        """
        params = SwooshParameters()

        self.assertEqual(params.d, 256)
        self.assertEqual(params.N, 32)
        self.assertEqual(int(params.q), int((2 ** 214) - 255))
        self.assertIsNotNone(params.q_ntt)
        self.assertEqual(params.key_bytes, 32)
        self.assertEqual(params.elem_bytes, 27)

        self.assertEqual(params.domain_base, b"Swoosh")
        self.assertEqual(params.domain_A, b"Swoosh|A")
        self.assertEqual(params.domain_sk, b"Swoosh|sk")
        self.assertEqual(params.domain_e, b"Swoosh|e")
        self.assertEqual(params.domain_offset, b"Swoosh|offset")

        self.assertIsInstance(params.seed_A, bytes)
        self.assertGreater(len(params.seed_A), 0)

    def test_with_N_returns_updated_copy(self):
        """
        Verifica que with_N devuelve una copia actualizada
        sin modificar la instancia original.
        """
        params = SwooshParameters()
        updated = params.with_N(1)

        self.assertEqual(params.N, 32)
        self.assertEqual(updated.N, 1)

        self.assertEqual(updated.d, params.d)
        self.assertEqual(updated.q, params.q)
        self.assertEqual(updated.seed_A, params.seed_A)

    def test_with_seed_A_returns_updated_copy(self):
        """
        Verifica que with_seed_A sustituye correctamente la semilla
        en una nueva copia.
        """
        params = SwooshParameters()
        new_seed = b"SEED-DE-PRUEBA-0000000000000000"

        updated = params.with_seed_A(new_seed)

        self.assertEqual(updated.seed_A, new_seed)
        self.assertEqual(params.seed_A, b"TFG-SWOOSH-SEED-A-00000000000000")

    def test_with_q_and_with_q_ntt_return_updated_copy(self):
        """
        Verifica que los métodos with_q y with_q_ntt actualizan
        únicamente el módulo correspondiente.
        """
        params = SwooshParameters()

        new_q = 123456789
        new_q_ntt = 987654321

        updated_q = params.with_q(new_q)
        updated_q_ntt = params.with_q_ntt(new_q_ntt)

        self.assertEqual(updated_q.q, new_q)
        self.assertEqual(updated_q.q_ntt, params.q_ntt)

        self.assertEqual(updated_q_ntt.q_ntt, new_q_ntt)
        self.assertEqual(updated_q_ntt.q, params.q)


if __name__ == "__main__":
    unittest.main()