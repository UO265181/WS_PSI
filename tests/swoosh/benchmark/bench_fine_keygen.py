import csv
import sys
import time
import secrets
from dataclasses import dataclass
from typing import List

from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackendFlint import BackendFlint
from Crypto.helpers.swoosh.SwooshBackendNTTBasic import BackendNTTBasic
from Crypto.helpers.swoosh.SwooshBackendNTTBasic2 import BackendNTTBasic2

from tests.swoosh.utility import (
    available_backends,
    derive_seed,
    mean,
)


N_VALUE = 32
ITERATIONS = 25
BACKENDS_TO_TEST = ["FLINT", "NTT", "NTT2"]


@dataclass
class KeyGenStats:
    total_seconds: float = 0.0
    seedgen_seconds: float = 0.0
    sampling_seconds: float = 0.0
    pk_compute_seconds: float = 0.0
    finalize_seconds: float = 0.0


class InstrumentedBackendFlint(BackendFlint):
    """
    Variante instrumentada de BackendFlint para medir keygen con desglose fino.
    """

    def keygen_instrumented(self, A) -> KeyGenStats:
        stats = KeyGenStats()
        t_total_0 = time.perf_counter()

        # 1. Generacion de noiseseed
        t0 = time.perf_counter()
        noiseseed = secrets.token_bytes(32)
        t1 = time.perf_counter()
        stats.seedgen_seconds += t1 - t0

        # 2. Muestreo
        t2 = time.perf_counter()

        if self.N == 1:
            skL = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=0, eta=1)
            skR = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=1, eta=1)
            eL = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=2, eta=1)
            eR = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=3, eta=1)
        else:
            skL = [
                self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=10 + i, eta=1)
                for i in range(self.N)
            ]
            skR = [
                self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=20 + i, eta=1)
                for i in range(self.N)
            ]
            eL = [
                self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=30 + i, eta=1)
                for i in range(self.N)
            ]
            eR = [
                self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=40 + i, eta=1)
                for i in range(self.N)
            ]

        t3 = time.perf_counter()
        stats.sampling_seconds += t3 - t2

        # 3. Calculo algebraico de pk
        t4 = time.perf_counter()

        if self.N == 1:
            pkL_raw = self.mul_rq(A, skL)
            pkR_raw = self.mul_rq(A, skR)
        else:
            pkL_raw = self._vecmat(skL, A)
            pkR_raw = self._matvec(A, skR)

        t5 = time.perf_counter()
        stats.pk_compute_seconds += t5 - t4

        # 4. Finalizacion
        t6 = time.perf_counter()

        if self.N == 1:
            pkL = self.add_rq(pkL_raw, eL)
            pkR = self.add_rq(pkR_raw, eR)
            _ = ((skL, skR), (pkL, pkR))
        else:
            pkL = [self.add_rq(pkL_raw[i], eL[i]) for i in range(self.N)]
            pkR = [self.add_rq(pkR_raw[i], eR[i]) for i in range(self.N)]
            _ = ((skL, skR), (pkL, pkR))

        t7 = time.perf_counter()
        stats.finalize_seconds += t7 - t6

        stats.total_seconds = time.perf_counter() - t_total_0
        return stats


class InstrumentedBackendNTT(BackendNTTBasic):
    """
    Variante instrumentada de BackendNTTBasic para medir keygen con desglose fino.
    """

    def keygen_instrumented(self, A) -> KeyGenStats:
        stats = KeyGenStats()
        t_total_0 = time.perf_counter()

        # 1. Generacion de noiseseed
        t0 = time.perf_counter()
        noiseseed = secrets.token_bytes(32)
        t1 = time.perf_counter()
        stats.seedgen_seconds += t1 - t0

        # 2. Muestreo
        t2 = time.perf_counter()

        if self.N == 1:
            skL = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=0, eta=1)
            skR = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=1, eta=1)
            eL = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=2, eta=1)
            eR = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=3, eta=1)
        else:
            skL = [
                self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=10 + i, eta=1)
                for i in range(self.N)
            ]
            skR = [
                self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=20 + i, eta=1)
                for i in range(self.N)
            ]
            eL = [
                self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=30 + i, eta=1)
                for i in range(self.N)
            ]
            eR = [
                self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=40 + i, eta=1)
                for i in range(self.N)
            ]

        t3 = time.perf_counter()
        stats.sampling_seconds += t3 - t2

        # 3. Calculo algebraico de pk
        t4 = time.perf_counter()

        if self.N == 1:
            pkL_raw = self.mul_rq(skL, A)
            pkR_raw = self.mul_rq(A, skR)
        else:
            pkL_raw = self._vecmat(skL, A)
            pkR_raw = self._matvec(A, skR)

        t5 = time.perf_counter()
        stats.pk_compute_seconds += t5 - t4

        # 4. Finalizacion
        t6 = time.perf_counter()

        if self.N == 1:
            pkL = self.add_rq(pkL_raw, eL)
            pkR = self.add_rq(pkR_raw, eR)
            _ = ((skL, skR), (pkL, pkR))
        else:
            pkL = [self.add_rq(pkL_raw[i], eL[i]) for i in range(self.N)]
            pkR = [self.add_rq(pkR_raw[i], eR[i]) for i in range(self.N)]
            _ = ((skL, skR), (pkL, pkR))

        t7 = time.perf_counter()
        stats.finalize_seconds += t7 - t6

        stats.total_seconds = time.perf_counter() - t_total_0
        return stats


class InstrumentedBackendNTT2(BackendNTTBasic2):
    """
    Variante instrumentada de BackendNTTBasic2 para medir keygen con desglose fino.

    La fase pk_compute_seconds mide la parte optimizada:
      - transformacion de A, skL y skR;
      - productos matriz-vector en dominio NTT;
      - acumulacion en dominio transformado;
      - inversa final por componente.
    """

    def keygen_instrumented(self, A) -> KeyGenStats:
        stats = KeyGenStats()
        t_total_0 = time.perf_counter()

        # 1. Generacion de noiseseed
        t0 = time.perf_counter()
        noiseseed = secrets.token_bytes(32)
        t1 = time.perf_counter()
        stats.seedgen_seconds += t1 - t0

        # 2. Muestreo
        t2 = time.perf_counter()

        if self.N == 1:
            skL = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=0, eta=1)
            skR = self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=1, eta=1)
            eL = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=2, eta=1)
            eR = self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=3, eta=1)
        else:
            skL = [
                self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=10 + i, eta=1)
                for i in range(self.N)
            ]
            skR = [
                self.sample_cbd_poly(self.p.domain_sk, noiseseed, nonce=20 + i, eta=1)
                for i in range(self.N)
            ]
            eL = [
                self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=30 + i, eta=1)
                for i in range(self.N)
            ]
            eR = [
                self.sample_cbd_poly(self.p.domain_e, noiseseed, nonce=40 + i, eta=1)
                for i in range(self.N)
            ]

        t3 = time.perf_counter()
        stats.sampling_seconds += t3 - t2

        # 3. Calculo algebraico de pk
        t4 = time.perf_counter()

        if self.N == 1:
            pkL_raw = self.mul_rq(skL, A)
            pkR_raw = self.mul_rq(A, skR)
        else:
            A_hat = self._mat_hat(A)
            skL_hat = self._vec_hat(skL)
            skR_hat = self._vec_hat(skR)

            pkL_raw = self._vecmat_hat(skL_hat, A_hat)
            pkR_raw = self._matvec_hat(A_hat, skR_hat)

        t5 = time.perf_counter()
        stats.pk_compute_seconds += t5 - t4

        # 4. Finalizacion
        t6 = time.perf_counter()

        if self.N == 1:
            pkL = self.add_rq(pkL_raw, eL)
            pkR = self.add_rq(pkR_raw, eR)
            _ = ((skL, skR), (pkL, pkR))
        else:
            pkL = [self.add_rq(pkL_raw[i], eL[i]) for i in range(self.N)]
            pkR = [self.add_rq(pkR_raw[i], eR[i]) for i in range(self.N)]
            _ = ((skL, skR), (pkL, pkR))

        t7 = time.perf_counter()
        stats.finalize_seconds += t7 - t6

        stats.total_seconds = time.perf_counter() - t_total_0
        return stats


def make_backend(backend_name: str, params: SwooshParameters):
    if backend_name == "FLINT":
        return InstrumentedBackendFlint(params)

    if backend_name == "NTT":
        return InstrumentedBackendNTT(params)

    if backend_name == "NTT2":
        return InstrumentedBackendNTT2(params)

    raise ValueError(f"Backend desconocido para esta prueba: {backend_name}")


class FineKeyGenBenchmark:
    """
    Benchmark fino de keygen para N fijo y backends Python.
    """

    def __init__(self, backends: List[str], iterations: int):
        self.backends = backends
        self.iterations = iterations
        self.writer = csv.writer(sys.stdout)

    def write_header(self) -> None:
        self.writer.writerow(
            [
                "row_type",
                "backend",
                "N",
                "iteration",
                "total_seconds",
                "seedgen_seconds",
                "sampling_seconds",
                "pk_compute_seconds",
                "finalize_seconds",
            ]
        )

    def write_iteration_row(
        self,
        backend_name: str,
        iteration: int,
        stats: KeyGenStats,
    ) -> None:
        self.writer.writerow(
            [
                "ITER",
                backend_name,
                N_VALUE,
                iteration,
                f"{stats.total_seconds:.6f}",
                f"{stats.seedgen_seconds:.6f}",
                f"{stats.sampling_seconds:.6f}",
                f"{stats.pk_compute_seconds:.6f}",
                f"{stats.finalize_seconds:.6f}",
            ]
        )

    def write_summary_row(
        self,
        backend_name: str,
        stats_list: List[KeyGenStats],
    ) -> None:
        total_avg = mean([s.total_seconds for s in stats_list])
        seedgen_avg = mean([s.seedgen_seconds for s in stats_list])
        sampling_avg = mean([s.sampling_seconds for s in stats_list])
        pk_compute_avg = mean([s.pk_compute_seconds for s in stats_list])
        finalize_avg = mean([s.finalize_seconds for s in stats_list])

        self.writer.writerow(
            [
                "SUMMARY",
                backend_name,
                N_VALUE,
                "",
                f"{total_avg:.6f}",
                f"{seedgen_avg:.6f}",
                f"{sampling_avg:.6f}",
                f"{pk_compute_avg:.6f}",
                f"{finalize_avg:.6f}",
            ]
        )

    def run(self) -> None:
        base_params = SwooshParameters().with_N(N_VALUE)
        base_seed = base_params.seed_A

        self.write_header()

        for backend_name in self.backends:
            stats_list: List[KeyGenStats] = []

            for i in range(self.iterations):
                seed_i = derive_seed(
                    base_seed=base_seed,
                    i=i,
                    outlen=len(base_seed),
                    context=b"Swoosh-Benchmark-fine-keygen",
                )

                params = base_params.with_seed_A(seed_i)

                backend = make_backend(backend_name, params)
                A = backend.setup_A(params.seed_A)

                stats = backend.keygen_instrumented(A)
                stats_list.append(stats)

                self.write_iteration_row(backend_name, i, stats)

            self.write_summary_row(backend_name, stats_list)


if __name__ == "__main__":
    benchmark = FineKeyGenBenchmark(
        backends=available_backends(BACKENDS_TO_TEST),
        iterations=ITERATIONS,
    )
    benchmark.run()