import importlib.util
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from Crypto.handlers.SwooshHandler import SwooshHandler
from Crypto.helpers.swoosh.SwooshHelper import SwooshHelper
from Crypto.helpers.swoosh.params import SwooshParameters


def rust_module_available() -> bool:
    return importlib.util.find_spec("pswoosh_ffi") is not None


class SpySwooshHandler(SwooshHandler):
    """
    Test double de tipo Spy para SwooshHandler.
    No envía mensajes por red. En su lugar, captura los mensajes salientes
    en memoria para que las pruebas puedan verificar el flujo del protocolo.
    """

    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)
        self.sent_messages = []

    def send_message(self, peer, ser_enc_res, implementation, peer_pubkey=None):
        """
        Sustituye el envío real por una captura en memoria.
        Esta implementación reproduce el formato esperado del mensaje,
        pero evita depender de Network.Node o de la red real.
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


class TestIntegrationHandlerHelper(unittest.TestCase):
    """
    Pruebas de integración entre SwooshHandler y SwooshHelper.
    Se utiliza un Spy para capturar mensajes sin red real y mocks para
    aislar las llamadas de logging/Firebase.
    """

    BASE_BACKENDS = ["FLINT", "NTT"]

    @classmethod
    def available_backends(cls):
        backends = list(cls.BASE_BACKENDS)
        if rust_module_available():
            backends.append("RUST")
        return backends

    @staticmethod
    def make_handler(node_id: str) -> SpySwooshHandler:
        return SpySwooshHandler(
            id=node_id,
            my_data=set(),
            domain=32,
            devices=[],
            results={},
        )

    @staticmethod
    def make_helper(backend_name: str, params: SwooshParameters) -> SwooshHelper:
        helper = SwooshHelper(backend=backend_name, params=params)
        # Se reinicia el estado para que la prueba controle explícitamente
        # el ciclo setup_A -> generate_keys -> derive_shared_key.
        helper.A = None
        helper._sk = None
        helper.public_key = None
        helper.shared_key = None

        return helper

    @staticmethod
    def mock_logging_dependencies():
        """
        Crea mocks para las dependencias externas de logging.
        Estas llamadas no forman parte del comportamiento criptográfico ni
        del flujo lógico que se quiere verificar en esta prueba.
        """
        stack = ExitStack()

        mocks = {
            "start_logging": stack.enter_context(patch("Logs.Logs.start_logging")),
            "stop_logging": stack.enter_context(patch("Logs.Logs.stop_logging")),
            "log_activity": stack.enter_context(patch("Logs.Logs.log_activity")),
            "log_result": stack.enter_context(patch("Logs.Logs.log_result")),
        }

        return stack, mocks

    def test_first_step_sends_public_key(self):
        """
        Verifica que intersection_first_step genera y envía una clave pública
        serializada en el mensaje correspondiente.
        """
        base_params = SwooshParameters()

        for backend in self.available_backends():
            N = 32 if backend == "RUST" else 2

            with self.subTest(backend=backend, N=N):
                params = base_params.with_N(N)
                handler = self.make_handler("[10.0.0.1]")
                helper = self.make_helper(backend, params)

                with self.mock_logging_dependencies()[0] as _:
                    sent_size, recv_size = handler.intersection_first_step(
                        "[10.0.0.2]",
                        helper,
                    )

                self.assertEqual(len(handler.sent_messages), 1)

                peer, message = handler.sent_messages[0]

                self.assertEqual(peer, "[10.0.0.2]")
                self.assertEqual(message["implementation"], helper.imp_name)
                self.assertEqual(message["peer"], "[10.0.0.1]")
                self.assertIn("pubkey", message)
                self.assertEqual(message["step"], "2")
                self.assertGreater(sent_size, 0)
                self.assertGreater(recv_size, 0)

    def test_second_step_sends_public_key_and_stores_shared_key(self):
        """
        Verifica que intersection_second_step envía la clave pública local
        y almacena la shared key cuando procede.
        """
        base_params = SwooshParameters()

        for backend in self.available_backends():
            N = 32 if backend == "RUST" else 2

            with self.subTest(backend=backend, N=N):
                params = base_params.with_N(N)

                alice_handler = self.make_handler("[10.0.0.1]")
                bob_handler = self.make_handler("[10.0.0.2]")

                alice = self.make_helper(backend, params)
                bob = self.make_helper(backend, params)

                alice.setup_A()
                bob.setup_A()

                alice.generate_keys()
                bob.generate_keys()

                alice_pub = alice.serialize_public_key()

                stack, mocks = self.mock_logging_dependencies()
                with stack:
                    _, recv_size = bob_handler.intersection_second_step(
                        "[10.0.0.1]",
                        bob,
                        peer_data=None,
                        peer_pubkey=alice_pub,
                    )

                self.assertEqual(len(bob_handler.sent_messages), 1)
                self.assertGreater(recv_size, 0)

                self.assertTrue(
                    any("SharedKey" in k for k in bob_handler.results.keys())
                )

                mocks["log_result"].assert_called()

    def test_final_step_computes_missing_shared_key(self):
        """
        Verifica que intersection_final_step calcula la shared key si todavía
        no estaba almacenada en los resultados.
        """
        base_params = SwooshParameters()

        for backend in self.available_backends():
            N = 32 if backend == "RUST" else 2

            with self.subTest(backend=backend, N=N):
                params = base_params.with_N(N)

                alice_handler = self.make_handler("[10.0.0.1]")
                bob_handler = self.make_handler("[10.0.0.2]")

                alice = self.make_helper(backend, params)
                bob = self.make_helper(backend, params)

                alice.setup_A()
                bob.setup_A()

                alice.generate_keys()
                bob.generate_keys()

                bob_pub = bob.serialize_public_key()

                stack, mocks = self.mock_logging_dependencies()
                with stack:
                    result = alice_handler.intersection_final_step(
                        "[10.0.0.2]",
                        alice,
                        bob_pub,
                    )

                self.assertEqual(result, (None, None))

                self.assertTrue(
                    any("SharedKey" in k for k in alice_handler.results.keys())
                )

                mocks["log_result"].assert_called()

    def test_handler_helper_end_to_end_message_flow(self):
        """
        Verifica el flujo mínimo first_step -> second_step -> final_step
        entre dos handlers con helpers reales, sin red real.
        """
        base_params = SwooshParameters()

        for backend in self.available_backends():
            N = 32 if backend == "RUST" else 2

            with self.subTest(backend=backend, N=N):
                params = base_params.with_N(N)

                alice_handler = self.make_handler("[10.0.0.1]")
                bob_handler = self.make_handler("[10.0.0.2]")

                alice = self.make_helper(backend, params)
                bob = self.make_helper(backend, params)

                stack, _mocks = self.mock_logging_dependencies()
                with stack:
                    # Paso 1: Alice envía su clave pública.
                    alice_handler.intersection_first_step("[10.0.0.2]", alice)
                    _, msg1 = alice_handler.sent_messages[-1]
                    alice_pub = msg1["pubkey"]

                    # Paso 2: Bob responde y deriva su shared key.
                    bob_handler.intersection_second_step(
                        "[10.0.0.1]",
                        bob,
                        None,
                        alice_pub,
                    )
                    _, msg2 = bob_handler.sent_messages[-1]
                    bob_pub = msg2["data"]

                    # Paso 3: Alice completa la derivación.
                    alice_handler.intersection_final_step(
                        "[10.0.0.2]",
                        alice,
                        bob_pub,
                    )

                self.assertTrue(
                    any("SharedKey" in k for k in alice_handler.results.keys())
                )
                self.assertTrue(
                    any("SharedKey" in k for k in bob_handler.results.keys())
                )


if __name__ == "__main__":
    unittest.main()