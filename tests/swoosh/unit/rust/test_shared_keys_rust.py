import importlib.util
import unittest

from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackendRust import (
    BackendRust,
    QuaresmaParameterMismatchError,
)


def rust_module_available() -> bool:
    return importlib.util.find_spec("pswoosh_ffi") is not None


@unittest.skipUnless(
    rust_module_available(),
    "pswoosh_ffi no está disponible; se omiten las pruebas de BackendRust.",
)
class TestSharedKeyRust(unittest.TestCase):
    """
    Pruebas unitarias sobre la derivación de shared key en BackendRust.
    """

    def make_backend(self, params: SwooshParameters | None = None) -> BackendRust:
        if params is None:
            params = SwooshParameters()
        return BackendRust(params)

    def make_role_keypair(self, backend: BackendRust, role: bool):
        backend.set_role(role)
        A_bundle = backend.setup_A(backend.p.seed_A)
        sk_bundle, pk_bundle = backend.keygen(A_bundle)
        sk_bytes = backend.serialize_sk(sk_bundle)
        pk_bytes = backend.serialize_pk(pk_bundle)
        return sk_bytes, pk_bytes

    def test_shared_key_requires_active_role(self):
        """
        Verifica que BackendRust no permite derivar la shared key
        si active_role es None.
        """
        alice = self.make_backend()
        bob = self.make_backend()

        # Generamos material criptográfico con roles válidos
        sk_a, pk_a = self.make_role_keypair(alice, True)
        _, pk_b = self.make_role_keypair(bob, False)

        # Dejamos a Alice sin rol activo antes de derivar
        alice.set_role(None)

        with self.assertRaises(QuaresmaParameterMismatchError):
            alice.derive_shared_key(sk_a, pk_a, pk_b)

    def test_shared_key_matches_between_complementary_roles(self):
        """
        Verifica que dos participantes con roles complementarios
        derivan exactamente la misma shared key.
        """
        alice = self.make_backend()
        bob = self.make_backend()

        sk_a, pk_a = self.make_role_keypair(alice, True)
        sk_b, pk_b = self.make_role_keypair(bob, False)

        shared_a = alice.derive_shared_key(sk_a, pk_a, pk_b)
        shared_b = bob.derive_shared_key(sk_b, pk_b, pk_a)

        self.assertEqual(shared_a, shared_b)
        self.assertGreater(len(shared_a), 0)

    def test_shared_key_length_matches_expected(self):
        """
        Verifica que la shared key derivada tiene el tamaño esperado.
        """
        alice = self.make_backend()
        bob = self.make_backend()

        sk_a, pk_a = self.make_role_keypair(alice, True)
        _, pk_b = self.make_role_keypair(bob, False)

        shared = alice.derive_shared_key(sk_a, pk_a, pk_b)

        self.assertIsInstance(shared, bytes)
        self.assertEqual(len(shared), alice.key_bytes)
        self.assertEqual(len(shared), alice.ffi.symbytes)

    def test_shared_key_is_deterministic_for_same_material(self):
        """
        Verifica que, reutilizando exactamente el mismo material
        criptográfico, la derivación devuelve siempre la misma shared key.
        """
        alice = self.make_backend()
        bob = self.make_backend()

        sk_a, pk_a = self.make_role_keypair(alice, True)
        _, pk_b = self.make_role_keypair(bob, False)

        shared_1 = alice.derive_shared_key(sk_a, pk_a, pk_b)
        shared_2 = alice.derive_shared_key(sk_a, pk_a, pk_b)

        self.assertEqual(shared_1, shared_2)

    def test_shared_key_differs_if_peer_public_key_changes(self):
        """
        Verifica que cambiar la clave pública del peer modifica
        la shared key derivada.
        """
        alice = self.make_backend()
        bob1 = self.make_backend()
        bob2 = self.make_backend()

        sk_a, pk_a = self.make_role_keypair(alice, True)
        _, pk_b1 = self.make_role_keypair(bob1, False)
        _, pk_b2 = self.make_role_keypair(bob2, False)

        shared_1 = alice.derive_shared_key(sk_a, pk_a, pk_b1)
        shared_2 = alice.derive_shared_key(sk_a, pk_a, pk_b2)

        self.assertNotEqual(shared_1, shared_2)

    def test_shared_key_bytes_can_be_reused_directly(self):
        """
        Verifica que la shared key derivada se devuelve en formato bytes
        y puede reutilizarse directamente como resultado binario.
        """
        alice = self.make_backend()
        bob = self.make_backend()

        sk_a, pk_a = self.make_role_keypair(alice, True)
        _, pk_b = self.make_role_keypair(bob, False)

        shared = alice.derive_shared_key(sk_a, pk_a, pk_b)

        self.assertIsInstance(shared, bytes)
        self.assertGreater(len(shared), 0)
        self.assertNotEqual(shared, b"")


if __name__ == "__main__":
    unittest.main()