from src.crypto import dh_generate_private_key, dh_generate_public_key, dh_compute_shared_secret, derive_key, aes_decrypt

class Node:
    """
    Represents a node in the network.
    Each node has a DH key pair and can negotiate per-circuit keys.
    """
    def __init__(self, node_id):
        self.node_id = node_id
        self.private_key = dh_generate_private_key()
        self.public_key = dh_generate_public_key(self.private_key)
        # circuit_id -> key
        self.circuit_keys = {}

    def receive_create_circuit(self, circuit_id, their_public):
        """
        Handle a CREATE request: perform DH to establish a shared key.
        """
        shared_secret = dh_compute_shared_secret(their_public, self.private_key)
        key = derive_key(shared_secret)
        self.circuit_keys[circuit_id] = key
        return self.public_key

    def receive_relay(self, circuit_id, data, next_node):
        """
        Receive an onion-wrapped message:
        - Decrypt one layer using the circuit key.
        - If next_node is None, we're the exit node and we deliver the message.
        - Otherwise, forward the peeled onion to next_node.
        """
        if circuit_id not in self.circuit_keys:
            # Unknown circuit
            return None

        key = self.circuit_keys[circuit_id]
        inner_data = aes_decrypt(key, data)

        if next_node is None:
            # Exit node: deliver message (plaintext)
            msg = inner_data.decode('utf-8', errors='replace')
            print(f"[Node {self.node_id} - EXIT] Delivered message: {msg}")
            return True
        else:
            # Forward to next node
            return next_node.receive_relay(circuit_id, inner_data, None)
