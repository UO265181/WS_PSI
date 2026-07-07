import time
from typing import Dict, List, Tuple

from Crypto.helpers.swoosh.params import SwooshParameters

from tests.swoosh.utility import (
    BenchmarkCsvWriter,
    available_backends,
    backend_supports_N,
    derive_seed,
    make_backend,
    mean,
)


N_TO_TEST = [
    1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32,
]

ITERATIONS_PER_N = 25
BASE_BACKENDS = ["FLINT", "NTT", "NTT2", "RUST"]
PRINT_EACH_ITER = True
WRITE_SKIP_ROWS = True


class DeriveSharedKeyBenchmark:
    """
    Benchmark de rendimiento del método derive_shared_key() para los backends.

    La medición aísla exclusivamente derive_shared_key(); setup_A() y keygen()
    se ejecutan fuera de la región temporizada.
    """

    def __init__(
        self,
        backends: List[str],
        n_values: List[int],
        iterations: int,
    ):
        self.backends = backends
        self.n_values = n_values
        self.iterations = iterations
        self.csv = BenchmarkCsvWriter()

    def prepare_material(
        self,
        backend_name: str,
        params: SwooshParameters,
    ) -> Tuple[object, bytes, bytes, bytes, object, bytes, bytes, bytes]:
        """
        Prepara el material criptográfico de Alice y Bob fuera de la región
        temporizada.

        Devuelve:
            alice, sk_alice, pk_alice, peer_pk_for_alice,
            bob, sk_bob, pk_bob, peer_pk_for_bob
        """
        if backend_name == "RUST":
            alice = make_backend(backend_name, params, role=True)
            bob = make_backend(backend_name, params, role=False)
        else:
            alice = make_backend(backend_name, params)
            bob = make_backend(backend_name, params)

        A_alice = alice.setup_A(params.seed_A)
        A_bob = bob.setup_A(params.seed_A)

        sk_alice_obj, pk_alice_obj = alice.keygen(A_alice)
        sk_bob_obj, pk_bob_obj = bob.keygen(A_bob)

        sk_alice = alice.serialize_sk(sk_alice_obj)
        pk_alice = alice.serialize_pk(pk_alice_obj)

        sk_bob = bob.serialize_sk(sk_bob_obj)
        pk_bob = bob.serialize_pk(pk_bob_obj)

        return (
            alice,
            sk_alice,
            pk_alice,
            pk_bob,
            bob,
            sk_bob,
            pk_bob,
            pk_alice,
        )

    def run_once(self, backend_name: str, params: SwooshParameters) -> float:
        """
        Ejecuta una única medición de derive_shared_key().

        Para evitar sesgo entre lados del protocolo, mide Alice y Bob y toma
        como resultado la media de ambas derivaciones.
        """
        (
            alice,
            sk_alice,
            pk_alice,
            peer_pk_for_alice,
            bob,
            sk_bob,
            pk_bob,
            peer_pk_for_bob,
        ) = self.prepare_material(backend_name, params)

        t0 = time.perf_counter()
        alice.derive_shared_key(sk_alice, pk_alice, peer_pk_for_alice)
        t1 = time.perf_counter()

        t2 = time.perf_counter()
        bob.derive_shared_key(sk_bob, pk_bob, peer_pk_for_bob)
        t3 = time.perf_counter()

        return ((t1 - t0) + (t3 - t2)) / 2.0

    def run(self) -> Dict[Tuple[str, int], float]:
        base_params = SwooshParameters()
        base_seed = base_params.seed_A
        results: Dict[Tuple[str, int], float] = {}

        self.csv.write_header()

        for backend_name in self.backends:
            for n_value in self.n_values:
                if not backend_supports_N(backend_name, n_value):
                    if WRITE_SKIP_ROWS:
                        self.csv.write_skip(
                            backend_name,
                            n_value,
                            "backend_does_not_support_N",
                        )
                    continue

                times: List[float] = []

                for i in range(self.iterations):
                    seed_i = derive_seed(
                        base_seed=base_seed,
                        i=i,
                        outlen=len(base_seed),
                        context=b"Swoosh-Benchmark-derive_shared_key",
                    )

                    params = base_params.with_N(n_value).with_seed_A(seed_i)

                    dt = self.run_once(backend_name, params)
                    times.append(dt)

                    if PRINT_EACH_ITER:
                        self.csv.write_iteration(
                            backend_name=backend_name,
                            n_value=n_value,
                            iteration=i,
                            measure="derive_shared_key",
                            seconds=dt,
                        )

                avg = mean(times)
                results[(backend_name, n_value)] = avg

                self.csv.write_summary(
                    backend_name=backend_name,
                    n_value=n_value,
                    measure="derive_shared_key",
                    avg_seconds=avg,
                )

        return results


if __name__ == "__main__":
    benchmark = DeriveSharedKeyBenchmark(
        backends=available_backends(BASE_BACKENDS),
        n_values=N_TO_TEST,
        iterations=ITERATIONS_PER_N,
    )
    benchmark.run()