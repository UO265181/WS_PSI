import os
import time
from contextlib import ExitStack, redirect_stdout
from typing import Dict, List, Tuple
from unittest.mock import patch

from Crypto.handlers.SwooshHandler import SwooshHandler
from Crypto.helpers.swoosh.SwooshHelper import SwooshHelper
from Crypto.helpers.swoosh.params import SwooshParameters

from tests.swoosh.utility import (
    BenchmarkCsvWriter,
    available_backends,
    backend_supports_N,
    mean,
)


N_TO_TEST = [32]
ITERATIONS_PER_N = 5
BASE_BACKENDS = ["FLINT", "NTT", "NTT2", "RUST"]
PRINT_EACH_ITER = True
WRITE_SKIP_ROWS = False
WARMUP_ITERATIONS = 2


class SpySwooshHandler(SwooshHandler):
    """
    Test double de tipo Spy para SwooshHandler.

    Captura los mensajes salientes en memoria, evitando el envío real por red.
    Esto permite medir el flujo Handler-Helper sin depender de nodos reales ni
    de Network.Node.
    """

    def __init__(self, node_id: str, domain: int):
        super().__init__(
            id=node_id,
            my_data=set(),
            domain=domain,
            devices=[],
            results={},
        )
        self.sent_messages = []

    def send_message(self, peer, ser_enc_res, implementation, peer_pubkey=None):
        """
        Sustituye el envío real por una captura en memoria.

        Reproduce el formato esperado de los mensajes del protocolo, pero no
        utiliza red ni singleton Node.
        """
        if peer_pubkey:
            message = {
                "data": ser_enc_res,
                "implementation": implementation,
                "peer": self.id,
                "pubkey": peer_pubkey,
                "step": "2",
            }
        else:
            message = {
                "data": ser_enc_res,
                "implementation": implementation,
                "peer": self.id,
                "step": "F",
            }

        self.sent_messages.append((peer, message))
        return message


def make_handler(node_id: str, n_value: int) -> SpySwooshHandler:
    return SpySwooshHandler(node_id=node_id, domain=n_value)


def make_helper(
    backend_name: str,
    params: SwooshParameters,
    reset_crypto_state: bool = True,
) -> SwooshHelper:
    helper = SwooshHelper(backend=backend_name, params=params)

    if reset_crypto_state:
        helper.A = None
        helper._sk = None
        helper.public_key = None
        helper.shared_key = None

    return helper


def mock_logging_dependencies():
    """
    Crea mocks para las dependencias externas de logging/Firebase.
    """
    stack = ExitStack()

    stack.enter_context(patch("Logs.Logs.start_logging"))
    stack.enter_context(patch("Logs.Logs.stop_logging"))
    stack.enter_context(patch("Logs.Logs.log_activity"))
    stack.enter_context(patch("Logs.Logs.log_result"))

    return stack


def suppress_framework_stdout():
    """
    Redirige prints internos del framework a /dev/null para mantener limpia
    la salida CSV del benchmark.
    """
    devnull = open(os.devnull, "w")

    stack = ExitStack()
    stack.enter_context(devnull)
    stack.enter_context(redirect_stdout(devnull))

    return stack


class SwooshHandlerStepBenchmark:
    """
    Benchmark del flujo completo del protocolo a través de SwooshHandler,
    midiendo por separado cada paso del intercambio.

    Se mide:
      - intersection_first_step
      - intersection_second_step
      - intersection_final_step
      - total calculado como suma de los tres pasos

    No se usan nodos reales ni red.
    """

    def __init__(self, backends: List[str], n_values: List[int], iterations: int):
        self.backends = backends
        self.n_values = n_values
        self.iterations = iterations
        self.csv = BenchmarkCsvWriter()

    def run_once(self, backend_name: str, params: SwooshParameters) -> Dict[str, float]:
        n_value = params.N

        with suppress_framework_stdout():
            alice_handler = make_handler("[10.0.0.1]", n_value)
            bob_handler = make_handler("[10.0.0.2]", n_value)

            # Alice parte sin material criptográfico para que el primer paso
            # mida la generación/preparación de su clave pública.
            alice = make_helper(
                backend_name=backend_name,
                params=params,
                reset_crypto_state=True,
            )

            # Bob simula el estado habitual de un nodo ya inicializado:
            # su matriz A y sus claves ya están preparadas antes del intercambio.
            bob = make_helper(
                backend_name=backend_name,
                params=params,
                reset_crypto_state=True,
            )

            # Preparación de Bob fuera de la región temporizada.
            # Así el segundo paso mide el coste del paso del protocolo,
            # no el arranque criptográfico del nodo.
            bob.setup_A()
            bob.generate_keys()

        with mock_logging_dependencies(), suppress_framework_stdout():
            # Paso 1: Alice envía su clave pública.
            # En esta variante Alice sí genera/prepara su material en este paso.
            t0 = time.perf_counter()
            alice_handler.intersection_first_step("[10.0.0.2]", alice)
            t1 = time.perf_counter()

            _, msg1 = alice_handler.sent_messages[-1]
            alice_pub = msg1["pubkey"]

            # Paso 2: Bob responde con su clave pública ya preparada
            # y deriva la shared key.
            t2 = time.perf_counter()
            bob_handler.intersection_second_step("[10.0.0.1]", bob, None, alice_pub)
            t3 = time.perf_counter()

            _, msg2 = bob_handler.sent_messages[-1]
            bob_pub = msg2["data"]

            # Paso 3: Alice completa el intercambio.
            t4 = time.perf_counter()
            alice_handler.intersection_final_step("[10.0.0.2]", alice, bob_pub)
            t5 = time.perf_counter()

        if not any("SharedKey" in k for k in alice_handler.results.keys()):
            raise AssertionError(
                f"Alice no registró SharedKey en backend={backend_name}, N={n_value}"
            )

        if not any("SharedKey" in k for k in bob_handler.results.keys()):
            raise AssertionError(
                f"Bob no registró SharedKey en backend={backend_name}, N={n_value}"
            )

        first_step = t1 - t0
        second_step = t3 - t2
        final_step = t5 - t4
        total = first_step + second_step + final_step

        return {
            "handler_first_step": first_step,
            "handler_second_step": second_step,
            "handler_final_step": final_step,
            "handler_steps_total": total,
        }

    def run(self) -> Dict[Tuple[str, int, str], float]:
        results: Dict[Tuple[str, int, str], float] = {}

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

                params = SwooshParameters().with_N(n_value)

                collected: Dict[str, List[float]] = {
                    "handler_first_step": [],
                    "handler_second_step": [],
                    "handler_final_step": [],
                    "handler_steps_total": [],
                }

                for i in range(self.iterations):
                    step_times = self.run_once(backend_name, params)

                    for measure, seconds in step_times.items():
                        collected[measure].append(seconds)

                        if PRINT_EACH_ITER:
                            self.csv.write_iteration(
                                backend_name=backend_name,
                                n_value=n_value,
                                iteration=i,
                                measure=measure,
                                seconds=seconds,
                            )

                for measure, times in collected.items():
                    measured_times = times[WARMUP_ITERATIONS:]
                    avg = mean(measured_times)

                    results[(backend_name, n_value, measure)] = avg

                    self.csv.write_summary(
                        backend_name=backend_name,
                        n_value=n_value,
                        measure=measure,
                        avg_seconds=avg,
                    )

        return results


if __name__ == "__main__":
    benchmark = SwooshHandlerStepBenchmark(
        backends=available_backends(BASE_BACKENDS),
        n_values=N_TO_TEST,
        iterations=ITERATIONS_PER_N,
    )
    benchmark.run()