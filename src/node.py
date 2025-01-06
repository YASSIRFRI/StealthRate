# src/node.py
from src.crypto import (
    dh_compute_shared_secret,
    derive_key,
    aes_decrypt
)
from src.network import get_client

class Node:
    """
    Represents a node in the network.
    Each node can negotiate per-circuit keys and relay messages.
    """
    
    def __init__(self, node_id):
        self.node_id = node_id
        self.circuit_keys = {}

    def receive_create_circuit(self, circuit_id, their_public):
        """
        Handle a CREATE request: perform DH to establish a shared key.
        """
        from src.crypto import dh_generate_private_key, dh_generate_public_key
        private_key = dh_generate_private_key()
        public_key = dh_generate_public_key(private_key)
        shared_secret = dh_compute_shared_secret(their_public, private_key)
        key = derive_key(shared_secret)
        self.circuit_keys[circuit_id] = key
        print(f"[Node {self.node_id}] Established shared key for circuit {circuit_id.hex()}")
        return public_key

    def receive_relay(self, circuit_id, data, next_node, destination_client_id=None):
        """
        Receive an onion-wrapped message:
        - Decrypt one layer using the circuit key.
        - If next_node is None, we're the exit node and deliver the message.
        - Otherwise, forward the peeled onion to next_node.
        """
        if circuit_id not in self.circuit_keys:
            print(f"[Node {self.node_id}] Unknown circuit {circuit_id.hex()}.")
            return None

        key = self.circuit_keys[circuit_id]
        try:
            inner_data = aes_decrypt(key, data)
        except Exception as e:
            print(f"[Node {self.node_id}] Decryption failed for circuit {circuit_id.hex()}: {e}")
            return None

        print(f"[Node {self.node_id}] Decrypted layer: {inner_data.hex()}")

        if next_node is None:
            try:
                if len(inner_data) < 1:
                    raise ValueError("Message too short to contain destination client ID.")
                destination_id = inner_data[0]
                message = inner_data[1:].decode('utf-8')
                print(f"[Node {self.node_id} - EXIT] Delivering message to Client {destination_id}: {message}")
                destination_client = get_client(destination_id)
                if destination_client:
                    destination_client.receive_message(message)
                else:
                    print(f"[Node {self.node_id} - EXIT] Destination Client {destination_id} not found.")
            except Exception as e:
                print(f"[Node {self.node_id} - EXIT] Error delivering message: {e}")
            return True
        else:
            print(f"[Node {self.node_id}] Forwarding message to Node {next_node.node_id}")
            return next_node.receive_relay(circuit_id, inner_data, None, destination_client_id=destination_client_id)
