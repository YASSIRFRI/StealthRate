# client.py

import os

from cryptography import (
    dh_generate_private_key,
    dh_generate_public_key,
    dh_compute_shared_secret,
    derive_key,
    aes_encrypt
)
from registry import register_client, get_random_nodes

class Client:
    def __init__(self, client_id):
        if not (0 <= client_id <= 255):
            raise ValueError("client_id must be a single-byte integer (0-255).")
        self.client_id = client_id
        self.private_key = dh_generate_private_key()
        self.public_key = dh_generate_public_key(self.private_key)
        self.circuits = {} 
        register_client(self)

    def build_circuit(self, length=3):
        """
        Build a circuit of a given length by selecting random nodes.
        Perform a DH handshake with each hop to derive keys.
        Returns:
            path: list of nodes (entry -> ... -> exit)
            circuit_id: unique circuit identifier (bytes)
            keys: list of symmetric keys for each hop
        """
        path = get_random_nodes(length)
        circuit_id = os.urandom(4)  # 4-byte unique identifier
        keys = []

        print(f"\n[Client {self.client_id}] Building circuit...")
        for hop in path:
            priv = dh_generate_private_key()
            pub = dh_generate_public_key(priv)
            their_pub = hop.receive_create_circuit(circuit_id, pub)
            shared_secret = dh_compute_shared_secret(their_pub, priv)
            key = derive_key(shared_secret)
            keys.append(key)
            print(f"[Client {self.client_id}] Established key with Node {hop.node_id} for circuit {circuit_id.hex()}")

        self.circuits[circuit_id] = keys
        chosen_ids = [node.node_id for node in path]
        print(f"[Client {self.client_id}] Built circuit through Nodes: {chosen_ids}")
        return path, circuit_id, keys

    def send_onion_message(self, path, circuit_id, keys, message, destination_client_id):
        """
        Onion-encrypt the message using the keys in reverse order and send it.
        """
        if not (0 <= destination_client_id <= 255):
            raise ValueError("Destination client ID must be a single-byte integer (0-255).")

        # Construct message: first byte is destination client id, followed by message bytes
        dest_id_byte = destination_client_id.to_bytes(1, 'big')
        message_bytes = message  # Assume message is bytes
        data = dest_id_byte + message_bytes
        print(f"\n[Client {self.client_id}] Sending message: {data.hex()} to Client {destination_client_id}")

        # Encrypt layers from exit to entry
        for i, key in enumerate(reversed(keys)):
            data = aes_encrypt(key, data)
            print(f"[Client {self.client_id}] After encryption layer {i+1}: {data.hex()}")

        # Send to the first node with the remaining path
        remaining_path = path[1:]
        first_node = path[0]
        print(f"[Client {self.client_id}] Sending onion to Node {first_node.node_id}")
        first_node.receive_relay(circuit_id, data, remaining_path)

    def receive_message(self, message):
        """
        Decode and display the received message.
        """
        try:
            message_str = message.decode('utf-8')
            print(f"[Client {self.client_id}] Received message: {message_str}")
        except UnicodeDecodeError:
            print(f"[Client {self.client_id}] Received message (unable to decode): {message.hex()}")
