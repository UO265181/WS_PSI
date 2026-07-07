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


N_TO_TEST = [32]
# N_TO_TEST = [
#     1, 2, 3, 4, 5, 6, 7, 8,
#     9, 10, 11, 12, 13, 14, 15, 16,
#     17, 18, 19, 20, 21, 22, 23, 24,
#     25, 26, 27, 28, 29, 30, 31, 32,
# ]

ITERATIONS_PER_N = 5
BASE_BACKENDS = ["RUST", "NTT", "NTT2"]

PRINT_EACH_ITER = True
WRITE_SKIP_ROWS = True


class SetupABenchmark:
    """
    Benchmark de rendimiento del método setup_A() para los distintos backends.

    La salida se emite en formato CSV para facilitar su importación en Excel.
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

    def run_once(self, backend_name: str, params: SwooshParameters) -> float:
        """
        Ejecuta una única medición de setup_A().
        """
        backend = make_backend(backend_name, params)

        t0 = time.perf_counter()
        backend.setup_A(params.seed_A)
        t1 = time.perf_counter()

        return t1 - t0

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
                        context=b"Swoosh-Benchmark-setup_A",
                    )

                    params = base_params.with_N(n_value).with_seed_A(seed_i)

                    dt = self.run_once(backend_name, params)
                    times.append(dt)

                    if PRINT_EACH_ITER:
                        self.csv.write_iteration(
                            backend_name=backend_name,
                            n_value=n_value,
                            iteration=i,
                            measure="setup_A",
                            seconds=dt,
                        )

                avg = mean(times)
                results[(backend_name, n_value)] = avg

                self.csv.write_summary(
                    backend_name=backend_name,
                    n_value=n_value,
                    measure="setup_A",
                    avg_seconds=avg,
                )

        return results


if __name__ == "__main__":
    benchmark = SetupABenchmark(
        backends=available_backends(
            base_backends=BASE_BACKENDS
        ),
        n_values=N_TO_TEST,
        iterations=ITERATIONS_PER_N,
    )
    benchmark.run()