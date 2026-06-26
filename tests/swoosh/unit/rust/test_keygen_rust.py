import importlib.util
import unittest

from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackendRust import (
    BackendRust,
    RustABundle,
    RustKeyBundle,
)


def rust_module_available() -> bool:
    return importlib.util.find_spec("pswoosh_ffi") is not None


@unittest.skipUnless(
    rust_module_available(),
    "pswoosh_ffi no está disponible; se omiten las pruebas de BackendRust.",
)
class TestKeyGenRust(unittest.TestCase):
    """
    Pruebas unitarias sobre la generación de claves en BackendRust.
    """

    def make_backend(self, params: SwooshParameters | None = None) -> BackendRust:
        if params is None:
            params = SwooshParameters()
        return BackendRust(params)

    def prepare_A(self, backend: BackendRust) -> RustABundle:
        return backend.setup_A(backend.p.seed_A)

    def test_keygen_unspecialized_generates_both_roles(self):
        """
        Verifica que, si active_role es None, keygen produce claves
        para ambas cardinalidades.
        """
        backend = self.make_backend()
        self.assertIsNone(backend.get_role())

        A_bundle = self.prepare_A(backend)
        sk_bundle, pk_bundle = backend.keygen(A_bundle)

        self.assertIsInstance(sk_bundle, RustKeyBundle)
        self.assertIsInstance(pk_bundle, RustKeyBundle)

        self.assertIn(True, sk_bundle.sk_by_role)
        self.assertIn(False, sk_bundle.sk_by_role)

        self.assertIn(True, pk_bundle.pk_by_role)
        self.assertIn(False, pk_bundle.pk_by_role)

        self.assertIsNotNone(sk_bundle.sk_by_role[True])
        self.assertIsNotNone(sk_bundle.sk_by_role[False])
        self.assertIsNotNone(pk_bundle.pk_by_role[True])
        self.assertIsNotNone(pk_bundle.pk_by_role[False])

    def test_keygen_with_true_role_generates_single_orientation(self):
        """
        Verifica que, si active_role=True, keygen genera únicamente
        la cardinalidad correspondiente a ese rol.
        """
        backend = self.make_backend()
        backend.set_role(True)

        A_bundle = self.prepare_A(backend)
        sk_bundle, pk_bundle = backend.keygen(A_bundle)

        self.assertIn(True, sk_bundle.sk_by_role)
        self.assertNotIn(False, sk_bundle.sk_by_role)

        self.assertIn(True, pk_bundle.pk_by_role)
        self.assertNotIn(False, pk_bundle.pk_by_role)

    def test_keygen_with_false_role_generates_single_orientation(self):
        """
        Verifica que, si active_role=False, keygen genera únicamente
        la cardinalidad correspondiente a ese rol.
        """
        backend = self.make_backend()
        backend.set_role(False)

        A_bundle = self.prepare_A(backend)
        sk_bundle, pk_bundle = backend.keygen(A_bundle)

        self.assertIn(False, sk_bundle.sk_by_role)
        self.assertNotIn(True, sk_bundle.sk_by_role)

        self.assertIn(False, pk_bundle.pk_by_role)
        self.assertNotIn(True, pk_bundle.pk_by_role)

    def test_keygen_updates_last_key_bundle(self):
        """
        Verifica que el backend conserva el último bundle de claves generado.
        """
        backend = self.make_backend()
        A_bundle = self.prepare_A(backend)

        sk_bundle, pk_bundle = backend.keygen(A_bundle)

        self.assertIs(backend._last_key_bundle, sk_bundle)
        self.assertIs(sk_bundle, pk_bundle)

    def test_serialize_sk_returns_bytes(self):
        """
        Verifica que serialize_sk devuelve un bloque de bytes no vacío.
        """
        backend = self.make_backend()
        A_bundle = self.prepare_A(backend)
        sk_bundle, _ = backend.keygen(A_bundle)

        serialized = backend.serialize_sk(sk_bundle)

        self.assertIsInstance(serialized, bytes)
        self.assertGreater(len(serialized), 0)

    def test_serialize_pk_returns_bytes(self):
        """
        Verifica que serialize_pk devuelve un bloque de bytes no vacío.
        """
        backend = self.make_backend()
        A_bundle = self.prepare_A(backend)
        _, pk_bundle = backend.keygen(A_bundle)

        serialized = backend.serialize_pk(pk_bundle)

        self.assertIsInstance(serialized, bytes)
        self.assertGreater(len(serialized), 0)

    def test_serialized_key_sizes_match_ffi_constants(self):
        """
        Verifica que los tamaños de sk y pk serializadas coinciden con
        los tamaños expuestos por la capa FFI.
        """
        backend = self.make_backend()
        A_bundle = self.prepare_A(backend)
        sk_bundle, pk_bundle = backend.keygen(A_bundle)

        sk_bytes = backend.serialize_sk(sk_bundle)
        pk_bytes = backend.serialize_pk(pk_bundle)

        self.assertEqual(len(sk_bytes), backend.ffi.secretkey_bytes)
        self.assertEqual(len(pk_bytes), backend.ffi.publickey_bytes)

    def test_serialize_respects_active_role_for_sk(self):
        """
        Verifica que serialize_sk usa la cardinalidad asociada al rol activo.
        """
        backend = self.make_backend()
        A_bundle = self.prepare_A(backend)
        sk_bundle, _ = backend.keygen(A_bundle)

        backend.set_role(True)
        sk_true = backend.serialize_sk(sk_bundle)

        backend.set_role(False)
        sk_false = backend.serialize_sk(sk_bundle)

        self.assertIsInstance(sk_true, bytes)
        self.assertIsInstance(sk_false, bytes)
        self.assertNotEqual(sk_true, sk_false)

    def test_serialize_respects_active_role_for_pk(self):
        """
        Verifica que serialize_pk usa la cardinalidad asociada al rol activo.
        """
        backend = self.make_backend()
        A_bundle = self.prepare_A(backend)
        _, pk_bundle = backend.keygen(A_bundle)

        backend.set_role(True)
        pk_true = backend.serialize_pk(pk_bundle)

        backend.set_role(False)
        pk_false = backend.serialize_pk(pk_bundle)

        self.assertIsInstance(pk_true, bytes)
        self.assertIsInstance(pk_false, bytes)
        self.assertNotEqual(pk_true, pk_false)

    def test_deserialize_sk_and_pk_return_bytes(self):
        """
        Verifica que la deserialización en BackendRust devuelve bytes crudos.
        """
        backend = self.make_backend()
        A_bundle = self.prepare_A(backend)
        sk_bundle, pk_bundle = backend.keygen(A_bundle)

        sk_bytes = backend.serialize_sk(sk_bundle)
        pk_bytes = backend.serialize_pk(pk_bundle)

        restored_sk = backend.deserialize_sk(sk_bytes)
        restored_pk = backend.deserialize_pk(pk_bytes)

        self.assertEqual(restored_sk, sk_bytes)
        self.assertEqual(restored_pk, pk_bytes)

    def test_keygen_requires_valid_A_bundle(self):
        """
        Verifica que keygen rechaza objetos que no sean RustABundle.
        """
        backend = self.make_backend()

        with self.assertRaises(TypeError):
            backend.keygen(object())


if __name__ == "__main__":
    unittest.main()