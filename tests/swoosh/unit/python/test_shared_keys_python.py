import unittest
from typing import Dict

from Crypto.helpers.swoosh.SwooshHelper import SwooshHelper
from Crypto.helpers.swoosh.params import SwooshParameters


class TestSharedKeyPython(unittest.TestCase):
    """
    Pruebas unitarias sobre la derivación de la shared key
    en los backends Python de SWOOSH.
    """

    BACKENDS_TO_TEST = ["FLINT", "NTT"]
    N_VALUES = [1, 16, 32]

    @staticmethod
    def make_helper(backend_name: str, params: SwooshParameters) -> SwooshHelper:
        helper = SwooshHelper(backend=backend_name, params=params)
        helper.A = None
        helper._sk = None
        helper.public_key = None
        helper.shared_key = None
        return helper

    def test_shared_key_same_for_alice_and_bob(self):
        """
        Verifica que Alice y Bob derivan exactamente la misma shared key
        cuando comparten la misma seed_A y ejecutan el flujo correctamente.
        """
        base_params = SwooshParameters()

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)

                    alice = self.make_helper(backend, params)
                    bob = self.make_helper(backend, params)

                    # Ambos reconstruyen la misma A
                    alice.setup_A()
                    bob.setup_A()
                    self.assertEqual(alice.A, bob.A)

                    # Cada uno genera sus propias claves
                    alice.generate_keys()
                    bob.generate_keys()

                    # Intercambio de claves públicas
                    pk_alice = alice.serialize_public_key()
                    pk_bob = bob.serialize_public_key()

                    # Derivación en ambos extremos
                    sk_alice = alice.compute_shared_key(pk_bob)
                    sk_bob = bob.compute_shared_key(pk_alice)

                    self.assertEqual(
                        sk_alice,
                        sk_bob,
                        msg=f"La shared key no coincide en backend={backend}, N={N}"
                    )

    def test_shared_key_length_matches_key_bytes(self):
        """
        Verifica que la shared key derivada tiene el tamaño esperado.
        """
        base_params = SwooshParameters()

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)

                    alice = self.make_helper(backend, params)
                    bob = self.make_helper(backend, params)

                    alice.setup_A()
                    bob.setup_A()

                    alice.generate_keys()
                    bob.generate_keys()

                    pk_bob = bob.serialize_public_key()
                    shared = alice.compute_shared_key(pk_bob)

                    self.assertIsInstance(shared, bytes)
                    self.assertEqual(len(shared), params.key_bytes)

    def test_shared_key_accepts_serialized_and_raw_peer_public_key(self):
        """
        Verifica que derive_shared_key acepta tanto la clave pública del peer
        serializada en base64 como en su forma binaria.
        """
        base_params = SwooshParameters()

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)

                    alice = self.make_helper(backend, params)
                    bob = self.make_helper(backend, params)

                    alice.setup_A()
                    bob.setup_A()

                    alice.generate_keys()
                    bob.generate_keys()

                    # Forma serializada base64
                    pk_bob_serialized = bob.serialize_public_key()

                    # Forma binaria cruda
                    pk_bob_raw = bob.backend.serialize_pk(bob.public_key)

                    shared_from_serialized = alice.derive_shared_key(pk_bob_serialized)
                    shared_from_raw = alice.derive_shared_key(pk_bob_raw)

                    self.assertEqual(shared_from_serialized, shared_from_raw)

    def test_shared_key_rejects_empty_peer_public_key(self):
        """
        Verifica que la derivación rechaza una clave pública vacía o mal formada.
        """
        base_params = SwooshParameters()

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)
                    alice = self.make_helper(backend, params)

                    alice.setup_A()
                    alice.generate_keys()

                    with self.assertRaises(ValueError):
                        alice.compute_shared_key(b"")

    def test_shared_key_is_stored_in_helper_state(self):
        """
        Verifica que, tras derivar la clave compartida, esta queda almacenada
        también en el estado interno del helper.
        """
        base_params = SwooshParameters()

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)

                    alice = self.make_helper(backend, params)
                    bob = self.make_helper(backend, params)

                    alice.setup_A()
                    bob.setup_A()

                    alice.generate_keys()
                    bob.generate_keys()

                    pk_bob = bob.serialize_public_key()
                    shared = alice.compute_shared_key(pk_bob)

                    self.assertEqual(alice.shared_key, shared)

    def test_shared_key_results_can_be_serialized(self):
        """
        Verifica que la shared key derivada puede serializarse con el
        formato esperado por el framework.
        """
        base_params = SwooshParameters()

        for backend in self.BACKENDS_TO_TEST:
            for N in self.N_VALUES:
                with self.subTest(backend=backend, N=N):
                    params = base_params.with_N(N)

                    alice = self.make_helper(backend, params)
                    bob = self.make_helper(backend, params)

                    alice.setup_A()
                    bob.setup_A()

                    alice.generate_keys()
                    bob.generate_keys()

                    pk_bob = bob.serialize_public_key()
                    shared = alice.compute_shared_key(pk_bob)

                    serialized = alice.serialize_result(shared)

                    self.assertIsInstance(serialized, dict)
                    self.assertIn("shared_key", serialized)
                    self.assertIsInstance(serialized["shared_key"], str)
                    self.assertGreater(len(serialized["shared_key"]), 0)


if __name__ == "__main__":
    unittest.main()