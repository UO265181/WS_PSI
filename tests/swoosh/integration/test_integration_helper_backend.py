import importlib.util
import unittest

from Crypto.helpers.swoosh.SwooshHelper import SwooshHelper
from Crypto.helpers.swoosh.params import SwooshParameters


def rust_module_available() -> bool:
    return importlib.util.find_spec("pswoosh_ffi") is not None


class TestIntegrationHelperBackend(unittest.TestCase):
    """
    Pruebas de integración entre SwooshHelper y los backends reales.
    """

    BASE_BACKENDS = ["FLINT", "NTT"]
    N_VALUES = [1, 16, 32]

    @classmethod
    def available_backends(cls):
        backends = list(cls.BASE_BACKENDS)
        if rust_module_available():
            backends.append("RUST")
        return backends

    @staticmethod
    def make_helper(backend_name: str, params: SwooshParameters) -> SwooshHelper:
        helper = SwooshHelper(backend=backend_name, params=params)
        helper.A = None
        helper._sk = None
        helper.public_key = None
        helper.shared_key = None
        return helper

    def test_helper_initializes_backend_and_keys(self):
        """
        Verifica que el helper inicializa correctamente el backend y genera
        material criptográfico interno válido.
        """
        base_params = SwooshParameters()

        for backend in self.available_backends():
            for N in self.N_VALUES:
                if backend == "RUST" and N != 32:
                    continue

                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)
                    helper = self.make_helper(backend, params)

                    helper.setup_A()
                    sk, pk = helper.generate_keys()

                    self.assertIsNotNone(helper.backend)
                    self.assertIsNotNone(helper._sk)
                    self.assertIsNotNone(helper.public_key)
                    self.assertIsInstance(sk, bytes)
                    self.assertIsInstance(pk, bytes)

    def test_helper_public_key_roundtrip(self):
        """
        Verifica que la clave pública serializada por el helper puede
        reconstruirse y reutilizarse sin pérdida.
        """
        base_params = SwooshParameters()

        for backend in self.available_backends():
            for N in self.N_VALUES:
                if backend == "RUST" and N != 32:
                    continue

                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)
                    helper = self.make_helper(backend, params)

                    helper.setup_A()
                    helper.generate_keys()

                    pk_serialized = helper.serialize_public_key()
                    pk_restored = helper.reconstruct_public_key(pk_serialized)

                    self.assertIsInstance(pk_serialized, str)
                    self.assertIsInstance(pk_restored, bytes)
                    self.assertGreater(len(pk_restored), 0)

    def test_helper_backend_shared_key_consistency(self):
        """
        Verifica que dos helpers que usan el mismo backend y la misma seed_A
        derivan exactamente la misma shared key.
        """
        base_params = SwooshParameters()

        for backend in self.available_backends():
            for N in self.N_VALUES:
                if backend == "RUST" and N != 32:
                    continue

                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)

                    alice = self.make_helper(backend, params)
                    bob = self.make_helper(backend, params)

                    if backend == "RUST":
                        alice.backend.set_role(True)
                        bob.backend.set_role(False)

                    alice.setup_A()
                    bob.setup_A()

                    alice.generate_keys()
                    bob.generate_keys()

                    pk_alice = alice.serialize_public_key()
                    pk_bob = bob.serialize_public_key()

                    shared_alice = alice.compute_shared_key(pk_bob)
                    shared_bob = bob.compute_shared_key(pk_alice)

                    self.assertEqual(shared_alice, shared_bob)
                    self.assertEqual(alice.shared_key, shared_alice)
                    self.assertEqual(bob.shared_key, shared_bob)

    def test_helper_result_serialization_after_shared_key(self):
        """
        Verifica que el resultado derivado puede serializarse correctamente
        a través del helper.
        """
        base_params = SwooshParameters()

        for backend in self.available_backends():
            N = 32 if backend == "RUST" else 2

            with self.subTest(backend=backend, N=N):
                params = base_params.with_N(N)

                alice = self.make_helper(backend, params)
                bob = self.make_helper(backend, params)

                if backend == "RUST":
                    alice.backend.set_role(True)
                    bob.backend.set_role(False)

                alice.setup_A()
                bob.setup_A()

                alice.generate_keys()
                bob.generate_keys()

                shared = alice.compute_shared_key(bob.serialize_public_key())
                serialized = alice.serialize_result(shared)

                self.assertIsInstance(serialized, dict)
                self.assertIn("shared_key", serialized)
                self.assertIsInstance(serialized["shared_key"], str)
                self.assertGreater(len(serialized["shared_key"]), 0)


if __name__ == "__main__":
    unittest.main()