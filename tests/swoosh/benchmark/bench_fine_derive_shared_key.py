import csv
import sys
import time
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
class DeriveSharedKeyStats:
    total_seconds: float = 0.0
    cardinality_seconds: float = 0.0
    offset_seconds: float = 0.0
    deserialize_seconds: float = 0.0
    kprime_seconds: float = 0.0
    reconcile_seconds: float = 0.0


class InstrumentedMixin:
    """
    Mixin común para instrumentar derive_shared_key en backends Python.
    """

    def derive_shared_key_instrumented(
        self,
        my_sk: bytes,
        my_pk: bytes,
        peer_pk: bytes,
    ) -> DeriveSharedKeyStats:
        stats = DeriveSharedKeyStats()
        t_total_0 = time.perf_counter()

        # 1. Orden canónico de claves públicas
        t0 = time.perf_counter()
        pk1, pk2 = self.cardinality_by_bytes(my_pk, peer_pk)
        t1 = time.perf_counter()
        stats.cardinality_seconds += t1 - t0

        # 2. Construcción del offset
        t2 = time.perf_counter()
        r = self.offset_poly(self.p.domain_offset, pk1, pk2)
        t3 = time.perf_counter()
        stats.offset_seconds += t3 - t2

        # 3. Deserialización de material criptográfico
        t4 = time.perf_counter()
        pk_peer = self.deserialize_pk(peer_pk)
        sk_me = self.deserialize_sk(my_sk)
        t5 = time.perf_counter()
        stats.deserialize_seconds += t5 - t4

        # 4. Cálculo de k'
        t6 = time.perf_counter()
        kprime = self.kprime(pk_peer, sk_me, r)
        t7 = time.perf_counter()
        stats.kprime_seconds += t7 - t6

        # 5. Reconciliación final
        t8 = time.perf_counter()
        _ = self.reconcile(kprime)
        t9 = time.perf_counter()
        stats.reconcile_seconds += t9 - t8

        stats.total_seconds = time.perf_counter() - t_total_0
        return stats


class InstrumentedBackendFlint(InstrumentedMixin, BackendFlint):
    """
    Variante instrumentada de BackendFlint para medir derive_shared_key
    con desglose fino.
    """
    pass


class InstrumentedBackendNTT(InstrumentedMixin, BackendNTTBasic):
    """
    Variante instrumentada de BackendNTTBasic para medir derive_shared_key
    con desglose fino.
    """
    pass


class InstrumentedBackendNTT2(InstrumentedMixin, BackendNTTBasic2):
    """
    Variante instrumentada de BackendNTTBasic2 para medir derive_shared_key
    con desglose fino.

    Permite observar si la optimización del cálculo de k' mediante acumulación
    en dominio NTT también reduce el coste de derive_shared_key.
    """
    pass


def make_backend(backend_name: str, params: SwooshParameters):
    if backend_name == "FLINT":
        return InstrumentedBackendFlint(params)

    if backend_name == "NTT":
        return InstrumentedBackendNTT(params)

    if backend_name == "NTT2":
        return InstrumentedBackendNTT2(params)

    raise ValueError(f"Backend desconocido para esta prueba: {backend_name}")


class FineDeriveSharedKeyBenchmark:
    """
    Benchmark fino de derive_shared_key para N fijo y backends Python.
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
                "cardinality_seconds",
                "offset_seconds",
                "deserialize_seconds",
                "kprime_seconds",
                "reconcile_seconds",
            ]
        )

    def write_iteration_row(
        self,
        backend_name: str,
        iteration: int,
        stats: DeriveSharedKeyStats,
    ) -> None:
        self.writer.writerow(
            [
                "ITER",
                backend_name,
                N_VALUE,
                iteration,
                f"{stats.total_seconds:.6f}",
                f"{stats.cardinality_seconds:.6f}",
                f"{stats.offset_seconds:.6f}",
                f"{stats.deserialize_seconds:.6f}",
                f"{stats.kprime_seconds:.6f}",
                f"{stats.reconcile_seconds:.6f}",
            ]
        )

    def write_summary_row(
        self,
        backend_name: str,
        stats_list: List[DeriveSharedKeyStats],
    ) -> None:
        total_avg = mean([s.total_seconds for s in stats_list])
        cardinality_avg = mean([s.cardinality_seconds for s in stats_list])
        offset_avg = mean([s.offset_seconds for s in stats_list])
        deserialize_avg = mean([s.deserialize_seconds for s in stats_list])
        kprime_avg = mean([s.kprime_seconds for s in stats_list])
        reconcile_avg = mean([s.reconcile_seconds for s in stats_list])

        self.writer.writerow(
            [
                "SUMMARY",
                backend_name,
                N_VALUE,
                "",
                f"{total_avg:.6f}",
                f"{cardinality_avg:.6f}",
                f"{offset_avg:.6f}",
                f"{deserialize_avg:.6f}",
                f"{kprime_avg:.6f}",
                f"{reconcile_avg:.6f}",
            ]
        )

    def prepare_material(self, backend_name: str, params: SwooshParameters):
        """
        Prepara el material criptográfico fuera de la región instrumentada.
        """
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

        return alice, sk_alice, pk_alice, pk_bob, bob, sk_bob, pk_bob, pk_alice

    def run(self) -> None:
        base_params = SwooshParameters().with_N(N_VALUE)
        base_seed = base_params.seed_A

        self.write_header()

        for backend_name in self.backends:
            stats_list: List[DeriveSharedKeyStats] = []

            for i in range(self.iterations):
                seed_i = derive_seed(
                    base_seed=base_seed,
                    i=i,
                    outlen=len(base_seed),
                    context=b"Swoosh-Benchmark-fine-derive_shared_key",
                )

                params = base_params.with_seed_A(seed_i)

                (
                    alice,
                    sk_alice,
                    pk_alice,
                    pk_bob,
                    _bob,
                    _sk_bob,
                    _pk_bob,
                    _pk_alice,
                ) = self.prepare_material(backend_name, params)

                stats = alice.derive_shared_key_instrumented(
                    sk_alice,
                    pk_alice,
                    pk_bob,
                )

                stats_list.append(stats)
                self.write_iteration_row(backend_name, i, stats)

            self.write_summary_row(backend_name, stats_list)


if __name__ == "__main__":
    benchmark = FineDeriveSharedKeyBenchmark(
        backends=available_backends(BACKENDS_TO_TEST),
        iterations=ITERATIONS,
    )
    benchmark.run()