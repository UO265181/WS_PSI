import csv
import hashlib
import importlib.util
import sys
from typing import List, Optional

from Crypto.helpers.swoosh.params import SwooshParameters
from Crypto.helpers.swoosh.SwooshBackendFlint import BackendFlint
from Crypto.helpers.swoosh.SwooshBackendNTTBasic import BackendNTTBasic
from Crypto.helpers.swoosh.SwooshBackendNTTBasic2 import BackendNTTBasic2
from Crypto.helpers.swoosh.SwooshBackendRust import BackendRust


DEFAULT_PYTHON_BACKENDS = ["FLINT", "NTT", "NTT2"]


def rust_module_available() -> bool:
    """
    Comprueba si el módulo nativo pswoosh_ffi está disponible.
    """
    return importlib.util.find_spec("pswoosh_ffi") is not None



def available_backends(base_backends: Optional[List[str]] = None) -> List[str]:
    """
    Devuelve la lista de backends disponibles para una prueba.
    """
    if base_backends is None:
        base_backends = list(DEFAULT_PYTHON_BACKENDS)

    backends = []

    for backend_name in base_backends:
        if backend_name == "RUST" and not rust_module_available():
            continue

        backends.append(backend_name)

    return backends


    if include_rust and rust_module_available() and "RUST" not in backends:
        backends.append("RUST")

    return backends


def backend_supports_N(backend_name: str, n_value: int) -> bool:
    """
    Indica si un backend soporta un valor concreto de N.

    BackendRust solo soporta el caso nominal N=32.
    """
    if backend_name == "RUST" and n_value != 32:
        return False

    return True


def make_backend(backend_name: str, params: SwooshParameters):
    """
    Construye el backend correspondiente a partir de su identificador.
    """
    if backend_name == "FLINT":
        return BackendFlint(params)

    if backend_name == "NTT":
        return BackendNTTBasic(params)

    if backend_name == "NTT2":
        return BackendNTTBasic2(params)

    if backend_name == "RUST":
        backend = BackendRust(params)
        backend.set_role(True)
        return backend

    raise ValueError(f"Backend desconocido: {backend_name}")


def derive_seed(
    base_seed: bytes,
    i: int,
    outlen: int,
    context: bytes = b"Swoosh-Benchmark",
) -> bytes:
    """
    Deriva una semilla determinista para benchmarks.

    El parámetro context permite separar las semillas usadas por distintas
    pruebas sin cambiar la semilla base.
    """
    h = hashlib.shake_256()
    h.update(context)
    h.update(base_seed)
    h.update(i.to_bytes(4, "little"))
    return h.digest(outlen)


def mean(values: List[float]) -> float:
    """
    Calcula la media aritmética de una lista de valores.
    """
    return sum(values) / len(values) if values else 0.0


class BenchmarkCsvWriter:
    """
    Escritor CSV común para benchmarks simples.

    Formato:
        row_type, backend, N, iteration, measure, seconds
    """

    def __init__(self, output=sys.stdout):
        self.writer = csv.writer(output)

    def write_header(self) -> None:
        self.writer.writerow(
            [
                "row_type",
                "backend",
                "N",
                "iteration",
                "measure",
                "seconds",
            ]
        )

    def write_iteration(
        self,
        backend_name: str,
        n_value: int,
        iteration: int,
        measure: str,
        seconds: float,
    ) -> None:
        self.writer.writerow(
            [
                "ITER",
                backend_name,
                n_value,
                iteration,
                measure,
                f"{seconds:.6f}",
            ]
        )

    def write_summary(
        self,
        backend_name: str,
        n_value: int,
        measure: str,
        avg_seconds: float,
    ) -> None:
        self.writer.writerow(
            [
                "SUMMARY",
                backend_name,
                n_value,
                "",
                f"{measure}_avg",
                f"{avg_seconds:.6f}",
            ]
        )

    def write_skip(
        self,
        backend_name: str,
        n_value: int,
        reason: str,
    ) -> None:
        self.writer.writerow(
            [
                "SKIP",
                backend_name,
                n_value,
                "",
                reason,
                "",
            ]
        )