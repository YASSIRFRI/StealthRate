import os
from src.crypto import dh_generate_private_key, dh_generate_public_key, dh_compute_shared_secret, derive_key, aes_encrypt
from src.network import get_random_nodes

class Client:
    """
    The client can build circuits and send onion-encrypted messages.
    """

    def __init__(self, name="client"):
        self.name = name

    def build_circuit(self, length=3):
        """
        Build a circuit of a given length by selecting random nodes.
        Perform a DH handshake with each hop to derive keys.
        Returns:
            path: list of nodes (entry -> ... -> exit)
            circuit_id: unique circuit identifier
            keys: list of symmetric keys for each hop
        """
        path = get_random_nodes(length)
        circuit_id = os.urandom(4)
        keys = []

        # For each hop in the path, perform DH
        for hop in path:
            priv = dh_generate_private_key()
            pub = dh_generate_public_key(priv)
            their_pub = hop.receive_create_circuit(circuit_id, pub)
            shared_secret = dh_compute_shared_secret(their_pub, priv)
            key = derive_key(shared_secret)
            keys.append(key)

        return path, circuit_id, keys

    def send_onion_message(self, path, circuit_id, keys, message):
        """
        Onion-encrypt the message using the keys in reverse order and send it.
        """
        data = message.encode('utf-8')
        # Encrypt from the exit node key backwards to the entry node key
        for key in reversed(keys):
            data = aes_encrypt(key, data)

        # Send to the first node. It will recursively relay through the path.
        first_node = path[0]
        first_node.receive_relay(circuit_id, data, path[1] if len(path) > 1 else None)
