class IntersectionHandler:
    def __init__(self, id, my_data, domain, devices, results):
        # Añadimos las variables de instancia de la clase Node para facilitar el acceso a los datos
        self.id = id
        self.my_data = my_data
        self.domain = domain
        self.devices = devices
        self.results = results

    def send_message(self, peer, ser_enc_res, implementation, peer_pubkey=None):
        if peer_pubkey:
            message = {'data': ser_enc_res, 'implementation': implementation, 'peer': self.id,
                       'pubkey': peer_pubkey, 'step': '2'}
        else:
            message = {'data': ser_enc_res, 'implementation': implementation, 'peer': self.id, 'step': 'F'}

        # Para poder lanzar tests en terminal sin necesidad de levantar un Nodo
        try:
            from Network import Node
            node = Node.Node.getinstance()
        except Exception:
            node = None
        # El nodo no existe, se está lanzando un test. Se devuelve el mensaje
        if node is None:
            return message

        Node.Node.getinstance().send_message(peer, message)

    def intersection_first_step(self, device, cs):
        raise NotImplementedError

    def intersection_second_step(self, device, cs, peer_data, pubkey):
        raise NotImplementedError

    def intersection_final_step(self, device, cs, peer_data):
        raise NotImplementedError
