import hashlib
import unittest
from typing import Any

from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackendFlint import BackendFlint
from Crypto.helpers.swoosh.SwooshBackendNTTBasic import BackendNTTBasic


class TestSetupAPython(unittest.TestCase):
    """
    Pruebas unitarias sobre la construcción de la matriz pública A
    en los backends Python de SWOOSH.
    """

    BACKEND_CLASSES = {
        "FLINT": BackendFlint,
        "NTT": BackendNTTBasic,
    }

    N_VALUES = [1, 16, 32]

    @staticmethod
    def derive_seed(base_seed: bytes, i: int, outlen: int = 32) -> bytes:
        h = hashlib.shake_256()
        h.update(b"Swoosh-A-seed-derivation")
        h.update(base_seed)
        h.update(i.to_bytes(4, "little"))
        return h.digest(outlen)

    @classmethod
    def make_backend(cls, backend_name: str, params: SwooshParameters):
        backend_cls = cls.BACKEND_CLASSES[backend_name]
        return backend_cls(params)
    
    @classmethod
    def fingerprint_A(cls, A: Any) -> str:
        return hashlib.sha256(cls.flatten_A(A)).hexdigest()[:16]

    @staticmethod
    def flatten_A(A: Any) -> bytes:
        """
        Convierte la estructura A (polinomio o matriz de polinomios)
        a una representación binaria para comparar
        huellas entre ejecuciones.
        """
        def poly_to_bytes(poly) -> bytes:
            coeffs = list(poly.coeffs())
            return b"".join(int(c).to_bytes(32, "little", signed=False) for c in coeffs)

        # Caso N = 1: A es un único polinomio
        if hasattr(A, "coeffs"):
            return poly_to_bytes(A)

        # Caso N > 1: A es una matriz de polinomios
        chunks = []
        for row in A:
            for poly in row:
                chunks.append(poly_to_bytes(poly))
        return b"".join(chunks)



    def test_setup_A_same_seed_same_result(self):
        """
        Verifica que, para el mismo backend, N y seed_A,
        la construcción de A es determinista.
        """
        base_params = SwooshParameters()
        seed = base_params.seed_A

        for backend_name in self.BACKEND_CLASSES:
            for N in self.N_VALUES:
                with self.subTest(backend=backend_name, N=N):
                    params = base_params.with_N(N).with_seed_A(seed)

                    backend1 = self.make_backend(backend_name, params)
                    backend2 = self.make_backend(backend_name, params)

                    A1 = backend1.setup_A(seed)
                    A2 = backend2.setup_A(seed)

                    self.assertEqual(
                        A1,
                        A2,
                        msg=f"A no coincide para backend={backend_name}, N={N}"
                    )

    def test_setup_A_different_seed_different_result(self):
        """
        Verifica que, manteniendo backend y N,
        distintas semillas producen matrices públicas distintas.
        """
        base_params = SwooshParameters()
        base_seed = base_params.seed_A

        for backend_name in self.BACKEND_CLASSES:
            for N in self.N_VALUES:
                with self.subTest(backend=backend_name, N=N):
                    seed1 = self.derive_seed(base_seed, 1, len(base_seed))
                    seed2 = self.derive_seed(base_seed, 2, len(base_seed))

                    params1 = base_params.with_N(N).with_seed_A(seed1)
                    params2 = base_params.with_N(N).with_seed_A(seed2)

                    backend1 = self.make_backend(backend_name, params1)
                    backend2 = self.make_backend(backend_name, params2)

                    A1 = backend1.setup_A(seed1)
                    A2 = backend2.setup_A(seed2)

                    fp1 = self.fingerprint_A(A1)
                    fp2 = self.fingerprint_A(A2)

                    self.assertNotEqual(
                        fp1,
                        fp2,
                        msg=f"La huella de A no cambió para backend={backend_name}, N={N}"
                    )

    def test_setup_A_shape_matches_N(self):
        """
        Verifica que la forma de A coincide con el valor de N:
        - N = 1  -> polinomio
        - N > 1  -> matriz N x N
        """
        base_params = SwooshParameters()

        for backend_name in self.BACKEND_CLASSES:
            for N in self.N_VALUES:
                with self.subTest(backend=backend_name, N=N):
                    params = base_params.with_N(N)
                    backend = self.make_backend(backend_name, params)

                    A = backend.setup_A(params.seed_A)

                    if N == 1:
                        self.assertTrue(
                            hasattr(A, "coeffs"),
                            msg=f"Para N=1 se esperaba un polinomio en {backend_name}"
                        )
                    else:
                        self.assertIsInstance(
                            A,
                            list,
                            msg=f"Para N>1 se esperaba una matriz en {backend_name}"
                        )
                        self.assertEqual(len(A), N)
                        self.assertTrue(all(len(row) == N for row in A))

    def test_setup_A_two_participants_same_seed(self):
        """
        Simula dos participantes que comparten seed_A y comprueba
        que ambos reconstruyen exactamente la misma A.
        """
        base_params = SwooshParameters()

        for backend_name in self.BACKEND_CLASSES:
            for N in self.N_VALUES:
                with self.subTest(backend=backend_name, N=N):
                    params = base_params.with_N(N)

                    alice = self.make_backend(backend_name, params)
                    bob = self.make_backend(backend_name, params)

                    A_alice = alice.setup_A(params.seed_A)
                    A_bob = bob.setup_A(params.seed_A)

                    self.assertEqual(
                        self.fingerprint_A(A_alice),
                        self.fingerprint_A(A_bob),
                        msg=f"Alice y Bob no coinciden en backend={backend_name}, N={N}"
                    )


if __name__ == "__main__":
    unittest.main()