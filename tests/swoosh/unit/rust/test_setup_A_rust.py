import importlib.util
import unittest

from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackendRust import (
    BackendRust,
    QuaresmaParameterMismatchError,
    RustABundle,
)


def rust_module_available() -> bool:
    return importlib.util.find_spec("pswoosh_ffi") is not None


@unittest.skipUnless(
    rust_module_available(),
    "pswoosh_ffi no está disponible; se omiten las pruebas de BackendRust.",
)
class TestSetupARust(unittest.TestCase):
    """
    Pruebas unitarias sobre la construcción de A en BackendRust.
    """

    def make_backend(self, params: SwooshParameters | None = None) -> BackendRust:
        if params is None:
            params = SwooshParameters()
        return BackendRust(params)

    def test_setup_A_requires_valid_seed_length(self):
        """
        Verifica que setup_A rechaza semillas de longitud incorrecta.
        """
        backend = self.make_backend()
        invalid_seed = b"short-seed"

        with self.assertRaises(QuaresmaParameterMismatchError):
            backend.setup_A(invalid_seed)

    def test_setup_A_unspecialized_generates_both_roles(self):
        """
        Verifica que, si active_role es None, setup_A genera ambas
        cardinalidades y las encapsula en un RustABundle.
        """
        backend = self.make_backend()
        seed = backend.p.seed_A

        self.assertIsNone(backend.get_role())

        bundle = backend.setup_A(seed)

        self.assertIsInstance(bundle, RustABundle)
        self.assertIn(True, bundle.by_role)
        self.assertIn(False, bundle.by_role)

        self.assertIsNotNone(bundle.by_role[True])
        self.assertIsNotNone(bundle.by_role[False])

        self.assertIs(backend._last_A_bundle, bundle)

    def test_setup_A_with_true_role_generates_single_orientation(self):
        """
        Verifica que, si se fija active_role=True, setup_A solo genera
        la orientación correspondiente a ese rol.
        """
        backend = self.make_backend()
        seed = backend.p.seed_A

        backend.set_role(True)
        bundle = backend.setup_A(seed)

        self.assertIsInstance(bundle, RustABundle)
        self.assertIn(True, bundle.by_role)
        self.assertNotIn(False, bundle.by_role)

        self.assertIsNotNone(bundle.by_role[True])
        self.assertIs(backend._last_A_bundle, bundle)

    def test_setup_A_with_false_role_generates_single_orientation(self):
        """
        Verifica que, si se fija active_role=False, setup_A solo genera
        la orientación correspondiente a ese rol.
        """
        backend = self.make_backend()
        seed = backend.p.seed_A

        backend.set_role(False)
        bundle = backend.setup_A(seed)

        self.assertIsInstance(bundle, RustABundle)
        self.assertIn(False, bundle.by_role)
        self.assertNotIn(True, bundle.by_role)

        self.assertIsNotNone(bundle.by_role[False])
        self.assertIs(backend._last_A_bundle, bundle)

    def test_setup_A_returns_python_handles(self):
        """
        Verifica que los valores almacenados en RustABundle son objetos Python
        válidos expuestos por la capa FFI.
        """
        backend = self.make_backend()
        seed = backend.p.seed_A

        bundle = backend.setup_A(seed)

        for role, handle in bundle.by_role.items():
            with self.subTest(role=role):
                self.assertIsNotNone(handle)
                self.assertIn("MatrixHandle", repr(handle))

    def test_setup_A_role_can_be_changed_between_calls(self):
        """
        Verifica que el backend puede cambiar de rol entre llamadas sucesivas
        a setup_A y que el bundle resultante se ajusta al rol actual.
        """
        backend = self.make_backend()
        seed = backend.p.seed_A

        backend.set_role(True)
        bundle_true = backend.setup_A(seed)
        self.assertIn(True, bundle_true.by_role)
        self.assertNotIn(False, bundle_true.by_role)

        backend.set_role(False)
        bundle_false = backend.setup_A(seed)
        self.assertIn(False, bundle_false.by_role)
        self.assertNotIn(True, bundle_false.by_role)


if __name__ == "__main__":
    unittest.main()