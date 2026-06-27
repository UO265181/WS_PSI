import hashlib
import importlib.util
import unittest

from Crypto.helpers.swoosh.SwooshHelper import SwooshHelper
from Crypto.helpers.swoosh.params import SwooshParameters


def rust_module_available() -> bool:
    return importlib.util.find_spec("pswoosh_ffi") is not None


class TestCorrectnessSharedKeyPython(unittest.TestCase):
    """
    Prueba de corrección empírica del protocolo SWOOSH.

    Ejecuta múltiples iteraciones del intercambio con la configuración típica
    (N = 32 y parámetros por defecto) y verifica que Alice y Bob derivan
    siempre la misma shared key para cada backend disponible.
    """

    ITERATIONS = 1000
    BASE_BACKENDS = ["NTT"]
    N = 32

    @classmethod
    def available_backends(cls):
        backends = list(cls.BASE_BACKENDS)
        if rust_module_available():
            backends.append("RUST")
        return backends

    @staticmethod
    def derive_seed(base_seed: bytes, i: int, outlen: int) -> bytes:
        h = hashlib.shake_256()
        h.update(b"Swoosh-SharedKey-correctness")
        h.update(base_seed)
        h.update(i.to_bytes(4, "little"))
        return h.digest(outlen)

    @staticmethod
    def make_helper(backend_name: str, params: SwooshParameters) -> SwooshHelper:
        helper = SwooshHelper(backend=backend_name, params=params)
        return helper

    def run_exchange_once(self, backend_name: str, params: SwooshParameters):
        alice = self.make_helper(backend_name, params)
        bob = self.make_helper(backend_name, params)

        if backend_name == "RUST":
            alice.backend.set_role(True)
            bob.backend.set_role(False)

        # En FLINT y NTT verificar igualdad estructural.
        if backend_name != "RUST":
            self.assertEqual(alice.A, bob.A)

        pk_alice = alice.serialize_public_key()
        pk_bob = bob.serialize_public_key()

        shared_alice = alice.compute_shared_key(pk_bob)
        shared_bob = bob.compute_shared_key(pk_alice)

        return shared_alice, shared_bob

    def test_correctness_shared_key_soak(self):
        """
        Verifica empíricamente que la shared key coincide en un número elevado
        de iteraciones para la configuración típica del protocolo.
        """
        base_params = SwooshParameters().with_N(self.N)
        base_seed = base_params.seed_A

        for backend in self.available_backends():
            failures = []

            for i in range(self.ITERATIONS):
                print(f"iter={i}")
                with self.subTest(backend=backend, iteration=i):
                    seed_i = self.derive_seed(base_seed, i, len(base_seed))
                    params = base_params.with_seed_A(seed_i)

                    shared_alice, shared_bob = self.run_exchange_once(backend, params)

                    if not isinstance(shared_alice, bytes) or not isinstance(shared_bob, bytes):
                        failures.append(
                            f"iter={i}: shared key no devuelta como bytes"
                        )
                        continue

                    if len(shared_alice) != params.key_bytes:
                        failures.append(
                            f"iter={i}: longitud shared_alice={len(shared_alice)} "
                            f"distinta de key_bytes={params.key_bytes}"
                        )
                        continue

                    if len(shared_bob) != params.key_bytes:
                        failures.append(
                            f"iter={i}: longitud shared_bob={len(shared_bob)} "
                            f"distinta de key_bytes={params.key_bytes}"
                        )
                        continue

                    if shared_alice != shared_bob:
                        fp_a = hashlib.sha256(shared_alice).hexdigest()[:16]
                        fp_b = hashlib.sha256(shared_bob).hexdigest()[:16]
                        failures.append(
                            f"iter={i}: shared keys distintas "
                            f"(Alice={fp_a}, Bob={fp_b})"
                        )

            self.assertEqual(
                len(failures),
                0,
                msg=(
                    f"Se observaron fallos de corrección en backend={backend}.\n"
                    + "\n".join(failures[:10])
                    + ("\n..." if len(failures) > 10 else "")
                ),
            )


if __name__ == "__main__":
    unittest.main()