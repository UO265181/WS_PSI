import ipaddress
import sys

from Crypto.handlers.IntersectionHandler import IntersectionHandler
from Logs import Logs
from Logs.log_activity import log_activity
from Network.collections.DbConstants import VERSION


CALCULATE_SK_BEEING_PEER = True


class SwooshHandler(IntersectionHandler):
    """
    Handler del protocolo SWOOSH dentro del framework.
    Coordina el flujo asíncrono del intercambio de claves entre nodos
    y delega la lógica criptográfica concreta en el helper asociado.
    """

    def __init__(self, id, my_data, domain, devices, results):
        super().__init__(id, my_data, domain, devices, results)

    @log_activity("SWOOSH")
    def intersection_first_step(self, device, cs):
        """
        Primer paso del protocolo.
        Genera o recupera la clave pública local, fija el rol si el backend
        lo requiere y envía la clave pública serializada al peer.
        """
        if hasattr(cs.backend, "set_role"):
            cs.backend.set_role(self._resolve_rust_role(device))

        serialized_pubkey = cs.serialize_public_key()
        self.send_message(device, None, cs.imp_name, serialized_pubkey)

        return sys.getsizeof(serialized_pubkey), sys.getsizeof(serialized_pubkey)

    @log_activity("SWOOSH")
    def intersection_second_step(self, device, cs, peer_data, peer_pubkey):
        """
        Segundo paso del protocolo.
        Recibe la clave pública del peer, responde con la clave pública local y,
        opcionalmente, deriva ya la shared key.
        """
        if hasattr(cs.backend, "set_role"):
            cs.backend.set_role(self._resolve_rust_role(device))

        serialized_pubkey = cs.serialize_public_key()
        self.send_message(device, serialized_pubkey, cs.imp_name)

        if CALCULATE_SK_BEEING_PEER:
            peer_key_bytes = cs.reconstruct_public_key(peer_pubkey)
            shared_key_bytes = cs.compute_shared_key(peer_key_bytes)
            shared_key = cs.serialize_result(shared_key_bytes)

            key_label = f"{self.id}-{device} {cs.imp_name} SharedKey"
            self.results[key_label] = shared_key

            Logs.log_result(
                "NIKE_SWOOSH_" + cs.imp_name,
                self.results[key_label],
                VERSION,
                self.id,
                device,
            )

        return None, sys.getsizeof(serialized_pubkey)

    @log_activity("SWOOSH")
    def intersection_final_step(self, device, cs, peer_pubkey):
        """
        Paso final del protocolo.
        Si la shared key no ha sido derivada todavía,
        la calcula a partir de la clave pública recibida y registra el
        resultado final del intercambio.
        """
        key_label = f"{self.id}-{device} {cs.imp_name} SharedKey"

        if key_label not in self.results:
            if hasattr(cs.backend, "set_role"):
                cs.backend.set_role(self._resolve_rust_role(device))

            peer_key_bytes = cs.reconstruct_public_key(peer_pubkey)
            shared_key_bytes = cs.compute_shared_key(peer_key_bytes)
            shared_key = cs.serialize_result(shared_key_bytes)

            self.results[key_label] = shared_key

        Logs.log_result(
            "NIKE_SWOOSH_" + cs.imp_name,
            self.results[key_label],
            VERSION,
            self.id,
            device,
        )

        print(
            f"Intersection with {device} - {cs.imp_name} - "
            f"Result: {self.results[key_label]}"
        )
        return None, None

    def _resolve_rust_role(self, device: str) -> bool:
        """
        Resuelve de forma determinista el rol relativo entre nodos.
        Si los identificadores pueden interpretarse como direcciones IP,
        utiliza su orden natural. En caso contrario, aplica una comparación
        lexicográfica como mecanismo de respaldo para tests o entornos no-IP.
        """
        try:
            my_ip = ipaddress.ip_address(self.id.strip("[]"))
            peer_ip = ipaddress.ip_address(device.strip("[]"))
            return my_ip < peer_ip
        except ValueError:
            return self.id < device