import csv
import sys
import time
from dataclasses import dataclass
from typing import List

from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackendFlint import BackendFlint
from Crypto.helpers.swoosh.SwooshBackendNTTBasic import BackendNTTBasic, PolyNTT
from Crypto.helpers.swoosh.SwooshBackendNTTBasic2 import BackendNTTBasic2

from tests.swoosh.utility import (
    available_backends,
    derive_seed,
    mean,
)


N_VALUE = 32
ITERATIONS = 25
BACKENDS_TO_TEST = ["FLINT", "NTT"]
# BACKENDS_TO_TEST = ["FLINT", "NTT", "NTT2"]


@dataclass
class SetupAStats:
    total_seconds: float = 0.0
    shake_seconds: float = 0.0
    rejection_seconds: float = 0.0
    materialization_seconds: float = 0.0
    blocks_generated: int = 0
    coeffs_accepted: int = 0


class InstrumentedBackendFlint(BackendFlint):
    def setup_A_instrumented(self, seed_A: bytes) -> SetupAStats:
        stats = SetupAStats()
        t_total_0 = time.perf_counter()

        if self.N == 1:
            coeffs: List[int] = []
            ctr = 0

            while len(coeffs) < self.d:
                t0 = time.perf_counter()
                block = self._shake(
                    self.p.domain_base,
                    self.p.domain_A,
                    seed_A,
                    ctr.to_bytes(4, "little"),
                    outlen=self.elem_bytes,
                )
                t1 = time.perf_counter()

                stats.shake_seconds += t1 - t0
                stats.blocks_generated += 1
                ctr += 1

                t2 = time.perf_counter()
                u = int.from_bytes(block, "little")

                if u < self.T:
                    coeffs.append(u % self.q)
                    stats.coeffs_accepted += 1

                t3 = time.perf_counter()
                stats.rejection_seconds += t3 - t2

            t4 = time.perf_counter()
            _ = self.R(coeffs)
            t5 = time.perf_counter()

            stats.materialization_seconds += t5 - t4
            stats.total_seconds = time.perf_counter() - t_total_0
            return stats

        ctr = 0

        for i in range(self.N):
            for j in range(self.N):
                coeffs: List[int] = []

                while len(coeffs) < self.d:
                    t0 = time.perf_counter()
                    block = self._shake(
                        self.p.domain_base,
                        self.p.domain_A,
                        seed_A,
                        i.to_bytes(2, "little"),
                        j.to_bytes(2, "little"),
                        ctr.to_bytes(4, "little"),
                        outlen=self.elem_bytes,
                    )
                    t1 = time.perf_counter()

                    stats.shake_seconds += t1 - t0
                    stats.blocks_generated += 1
                    ctr += 1

                    t2 = time.perf_counter()
                    u = int.from_bytes(block, "little")

                    if u < self.T:
                        coeffs.append(u % self.q)
                        stats.coeffs_accepted += 1

                    t3 = time.perf_counter()
                    stats.rejection_seconds += t3 - t2

                t4 = time.perf_counter()
                _ = self.R(coeffs)
                t5 = time.perf_counter()

                stats.materialization_seconds += t5 - t4

        stats.total_seconds = time.perf_counter() - t_total_0
        return stats


class InstrumentedBackendNTT(BackendNTTBasic):
    def setup_A_instrumented(self, seed_A: bytes) -> SetupAStats:
        return setup_A_instrumented_ntt_like(self, seed_A)


class InstrumentedBackendNTT2(BackendNTTBasic2):
    def setup_A_instrumented(self, seed_A: bytes) -> SetupAStats:
        return setup_A_instrumented_ntt_like(self, seed_A)


def setup_A_instrumented_ntt_like(backend, seed_A: bytes) -> SetupAStats:
    """
    Instrumentación común para backends basados en PolyNTT.

    BackendNTTBasic y BackendNTTBasic2 comparten la misma lógica de setup_A,
    por lo que se reutiliza esta función para ambos.
    """
    stats = SetupAStats()
    t_total_0 = time.perf_counter()

    if backend.N == 1:
        coeffs: List[int] = []
        ctr = 0

        while len(coeffs) < backend.d:
            t0 = time.perf_counter()
            block = backend._shake(
                backend.p.domain_base,
                backend.p.domain_A,
                seed_A,
                ctr.to_bytes(4, "little"),
                outlen=backend.elem_bytes,
            )
            t1 = time.perf_counter()

            stats.shake_seconds += t1 - t0
            stats.blocks_generated += 1
            ctr += 1

            t2 = time.perf_counter()
            u = int.from_bytes(block, "little")

            if u < backend.T:
                coeffs.append(u % backend.q)
                stats.coeffs_accepted += 1

            t3 = time.perf_counter()
            stats.rejection_seconds += t3 - t2

        t4 = time.perf_counter()
        _ = PolyNTT(coeffs)
        t5 = time.perf_counter()

        stats.materialization_seconds += t5 - t4
        stats.total_seconds = time.perf_counter() - t_total_0
        return stats

    ctr = 0

    for i in range(backend.N):
        for j in range(backend.N):
            coeffs: List[int] = []

            while len(coeffs) < backend.d:
                t0 = time.perf_counter()
                block = backend._shake(
                    backend.p.domain_base,
                    backend.p.domain_A,
                    seed_A,
                    i.to_bytes(2, "little"),
                    j.to_bytes(2, "little"),
                    ctr.to_bytes(4, "little"),
                    outlen=backend.elem_bytes,
                )
                t1 = time.perf_counter()

                stats.shake_seconds += t1 - t0
                stats.blocks_generated += 1
                ctr += 1

                t2 = time.perf_counter()
                u = int.from_bytes(block, "little")

                if u < backend.T:
                    coeffs.append(u % backend.q)
                    stats.coeffs_accepted += 1

                t3 = time.perf_counter()
                stats.rejection_seconds += t3 - t2

            t4 = time.perf_counter()
            _ = PolyNTT(coeffs)
            t5 = time.perf_counter()

            stats.materialization_seconds += t5 - t4

    stats.total_seconds = time.perf_counter() - t_total_0
    return stats


def make_instrumented_backend(backend_name: str, params: SwooshParameters):
    if backend_name == "FLINT":
        return InstrumentedBackendFlint(params)

    if backend_name == "NTT":
        return InstrumentedBackendNTT(params)

    if backend_name == "NTT2":
        return InstrumentedBackendNTT2(params)

    raise ValueError(
        f"Backend desconocido para esta prueba fina de setup_A: {backend_name}"
    )


class FineSetupABenchmark:
    """
    Benchmark fino de setup_A para N fijo y backends Python.
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
                "shake_seconds",
                "rejection_seconds",
                "materialization_seconds",
                "blocks_generated",
                "coeffs_accepted",
                "acceptance_ratio",
            ]
        )

    def write_iteration_row(
        self,
        backend_name: str,
        iteration: int,
        stats: SetupAStats,
    ) -> None:
        ratio = (
            stats.coeffs_accepted / stats.blocks_generated
            if stats.blocks_generated > 0
            else 0.0
        )

        self.writer.writerow(
            [
                "ITER",
                backend_name,
                N_VALUE,
                iteration,
                f"{stats.total_seconds:.6f}",
                f"{stats.shake_seconds:.6f}",
                f"{stats.rejection_seconds:.6f}",
                f"{stats.materialization_seconds:.6f}",
                stats.blocks_generated,
                stats.coeffs_accepted,
                f"{ratio:.6f}",
            ]
        )

    def write_summary_row(
        self,
        backend_name: str,
        stats_list: List[SetupAStats],
    ) -> None:
        total_avg = mean([s.total_seconds for s in stats_list])
        shake_avg = mean([s.shake_seconds for s in stats_list])
        rejection_avg = mean([s.rejection_seconds for s in stats_list])
        materialization_avg = mean([s.materialization_seconds for s in stats_list])
        blocks_avg = mean([float(s.blocks_generated) for s in stats_list])
        coeffs_avg = mean([float(s.coeffs_accepted) for s in stats_list])

        ratio_avg = mean(
            [
                s.coeffs_accepted / s.blocks_generated
                if s.blocks_generated > 0
                else 0.0
                for s in stats_list
            ]
        )

        self.writer.writerow(
            [
                "SUMMARY",
                backend_name,
                N_VALUE,
                "",
                f"{total_avg:.6f}",
                f"{shake_avg:.6f}",
                f"{rejection_avg:.6f}",
                f"{materialization_avg:.6f}",
                f"{blocks_avg:.2f}",
                f"{coeffs_avg:.2f}",
                f"{ratio_avg:.6f}",
            ]
        )

    def run(self) -> None:
        base_params = SwooshParameters().with_N(N_VALUE)
        base_seed = base_params.seed_A

        self.write_header()

        for backend_name in self.backends:
            stats_list: List[SetupAStats] = []

            for i in range(self.iterations):
                seed_i = derive_seed(
                    base_seed=base_seed,
                    i=i,
                    outlen=len(base_seed),
                    context=b"Swoosh-Benchmark-fine-setup_A",
                )

                params = base_params.with_seed_A(seed_i)
                backend = make_instrumented_backend(backend_name, params)

                stats = backend.setup_A_instrumented(params.seed_A)
                stats_list.append(stats)

                self.write_iteration_row(backend_name, i, stats)

            self.write_summary_row(backend_name, stats_list)


if __name__ == "__main__":
    benchmark = FineSetupABenchmark(
        backends=available_backends(BACKENDS_TO_TEST),
        iterations=ITERATIONS,
    )
    benchmark.run()