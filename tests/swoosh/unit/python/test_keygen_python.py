import hashlib
import unittest
from typing import Tuple

from Crypto.helpers.swoosh.SwooshHelper import SwooshHelper
from Crypto.helpers.swoosh.params import SwooshParameters


class TestKeyGenPython(unittest.TestCase):
    """
    Pruebas unitarias sobre la generación de claves en los backends Python de SWOOSH.
    """

    BACKENDS_TO_TEST = ["FLINT", "NTT"]
    N_VALUES = [1, 16, 32]

    @staticmethod
    def derive_seed(base_seed: bytes, i: int, outlen: int) -> bytes:
        h = hashlib.shake_256()
        h.update(b"Swoosh-KeyGen-seed-derivation")
        h.update(base_seed)
        h.update(i.to_bytes(4, "little"))
        return h.digest(outlen)

    @staticmethod
    def make_helper(backend_name: str, params: SwooshParameters) -> SwooshHelper:
        helper = SwooshHelper(backend=backend_name, params=params)
        helper.A = None
        helper._sk = None
        helper.public_key = None
        helper.shared_key = None
        return helper

    @staticmethod
    def expected_key_size_bytes(params: SwooshParameters) -> int:
        """
        Calcula el tamaño esperado de pk y sk serializadas:
            2 * N * d * elem_bytes
        """
        poly_bytes = params.d * params.elem_bytes
        return 2 * params.N * poly_bytes

    def assert_roundtrip_pk(
        self,
        helper: SwooshHelper,
        pk_bytes: bytes,
    ):
        """
        Verifica que una clave pública se serializa y deserializa sin pérdida.
        """
        pk_obj = helper.backend.deserialize_pk(pk_bytes)
        restored = helper.backend.serialize_pk(pk_obj)
        self.assertEqual(restored, pk_bytes)

    def assert_roundtrip_sk(
        self,
        helper: SwooshHelper,
        sk_bytes: bytes,
    ):
        """
        Verifica que una clave secreta se serializa y deserializa sin pérdida.
        """
        sk_obj = helper.backend.deserialize_sk(sk_bytes)
        restored = helper.backend.serialize_sk(sk_obj)
        self.assertEqual(restored, sk_bytes)

    def test_keygen_returns_non_empty_keys(self):
        """
        Verifica que keygen produce claves pública y secreta no vacías
        en ambos backends Python.
        """
        base_params = SwooshParameters()

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)
                    helper = self.make_helper(backend, params)

                    helper.setup_A()
                    sk, pk = helper.generate_keys()

                    self.assertIsInstance(sk, bytes)
                    self.assertIsInstance(pk, bytes)
                    self.assertGreater(len(sk), 0)
                    self.assertGreater(len(pk), 0)

    def test_keygen_serialized_key_sizes_match_expected(self):
        """
        Verifica que el tamaño de pk y sk serializadas coincide con el esperado.
        """
        base_params = SwooshParameters()

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)
                    helper = self.make_helper(backend, params)

                    helper.setup_A()
                    sk, pk = helper.generate_keys()

                    expected_size = self.expected_key_size_bytes(params)

                    self.assertEqual(len(sk), expected_size)
                    self.assertEqual(len(pk), expected_size)

    def test_keygen_roundtrip_pk_and_sk(self):
        """
        Verifica que las claves generadas sobreviven correctamente
        a la serialización y deserialización.
        """
        base_params = SwooshParameters()

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)
                    helper = self.make_helper(backend, params)

                    helper.setup_A()
                    sk, pk = helper.generate_keys()

                    self.assert_roundtrip_sk(helper, sk)
                    self.assert_roundtrip_pk(helper, pk)

    def test_keygen_same_seed_same_A_but_independent_noise(self):
        """
        Verifica que, con la misma seed_A, ambos participantes comparten la misma A,
        pero la generación de claves produce claves distintas debido al ruido aleatorio.
        """
        base_params = SwooshParameters()
        base_seed = base_params.seed_A

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    seed = self.derive_seed(base_seed, N, len(base_seed))
                    params = base_params.with_N(N).with_seed_A(seed)

                    alice = self.make_helper(backend, params)
                    bob = self.make_helper(backend, params)

                    alice.setup_A()
                    bob.setup_A()

                    self.assertEqual(alice.A, bob.A)

                    sk_a, pk_a = alice.generate_keys()
                    sk_b, pk_b = bob.generate_keys()

                    self.assertNotEqual(
                        pk_a,
                        pk_b,
                        msg=f"Las claves públicas no deberían coincidir en backend={backend}, N={N}"
                    )
                    self.assertNotEqual(
                        sk_a,
                        sk_b,
                        msg=f"Las claves secretas no deberían coincidir en backend={backend}, N={N}"
                    )

    def test_keygen_different_seed_changes_public_key(self):
        """
        Verifica que, para el mismo backend y N, cambiar la seed_A
        cambia el resultado de la generación de claves.
        """
        base_params = SwooshParameters()
        base_seed = base_params.seed_A

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    seed1 = self.derive_seed(base_seed, 1, len(base_seed))
                    seed2 = self.derive_seed(base_seed, 2, len(base_seed))

                    params1 = base_params.with_N(N).with_seed_A(seed1)
                    params2 = base_params.with_N(N).with_seed_A(seed2)

                    helper1 = self.make_helper(backend, params1)
                    helper2 = self.make_helper(backend, params2)

                    helper1.setup_A()
                    helper2.setup_A()

                    _, pk1 = helper1.generate_keys()
                    _, pk2 = helper2.generate_keys()

                    fp1 = hashlib.sha256(pk1).hexdigest()
                    fp2 = hashlib.sha256(pk2).hexdigest()

                    self.assertNotEqual(
                        fp1,
                        fp2,
                        msg=f"La huella de pk no cambió en backend={backend}, N={N}"
                    )


if __name__ == "__main__":
    unittest.main()