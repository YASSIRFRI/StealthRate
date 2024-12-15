# onion_routing_simulation.py

import os
import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# -----------------------------
# Cryptographic Functions
# -----------------------------

# Diffie-Hellman Parameters
PRIME = 0xFFFFFFFB
GENERATOR = 5

def dh_generate_private_key():
    return int.from_bytes(os.urandom(32), 'big') % PRIME

def dh_generate_public_key(private_key, prime=PRIME, generator=GENERATOR):
    return pow(generator, private_key, prime)

def dh_compute_shared_secret(their_public, my_private, prime=PRIME):
    return pow(their_public, my_private, prime)

def derive_key(shared_secret):
    # Ensure shared_secret is converted to bytes correctly
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    return SHA256.new(secret_bytes).digest()

def aes_encrypt(key, plaintext: bytes) -> bytes:
    nonce = os.urandom(8)  # 64-bit nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return nonce + ciphertext

def aes_decrypt(key, ciphertext: bytes) -> bytes:
    nonce = ciphertext[:8]
    ciph = ciphertext[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciph)

# -----------------------------
# Network Simulation
# -----------------------------

# Global registries
NODES = {}
CLIENTS = {}

def register_node(node):
    NODES[node.node_id] = node

def register_client(client):
    CLIENTS[client.client_id] = client

def get_node(node_id):
    return NODES.get(node_id, None)

def get_client(client_id):
    return CLIENTS.get(client_id, None)

def get_random_nodes(count):
    node_ids = list(NODES.keys())
    if count > len(node_ids):
        raise ValueError("Not enough nodes to sample the requested number.")
    return [NODES[i] for i in random.sample(node_ids, count)]

# -----------------------------
# Node Class
# -----------------------------

class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        self.circuit_keys = {}   # circuit_id (bytes) -> key (bytes)

    def receive_create_circuit(self, circuit_id, their_public):
        """
        Handle a CREATE request: perform DH to establish a shared key.
        """
        # Generate a new DH key pair for this circuit
        private_key = dh_generate_private_key()
        public_key = dh_generate_public_key(private_key)
        # Compute shared secret
        shared_secret = dh_compute_shared_secret(their_public, private_key)
        key = derive_key(shared_secret)
        # Store the symmetric key for this circuit
        self.circuit_keys[circuit_id] = key
        print(f"[Node {self.node_id}] Established shared key for circuit {circuit_id.hex()}")
        return public_key

    def receive_relay(self, circuit_id, data, remaining_path):
        """
        Receive an onion-wrapped message:
        - Decrypt one layer using the circuit key.
        - If remaining_path is empty, we're the exit node and deliver the message.
        - Otherwise, forward the peeled onion to the next node in the path.
        """
        if circuit_id not in self.circuit_keys:
            print(f"[Node {self.node_id}] Unknown circuit {circuit_id.hex()}.")
            return

        key = self.circuit_keys[circuit_id]
        try:
            inner_data = aes_decrypt(key, data)
        except Exception as e:
            print(f"[Node {self.node_id}] Decryption failed for circuit {circuit_id.hex()}: {e}")
            return

        print(f"[Node {self.node_id}] Decrypted layer: {inner_data.hex()}")

        if not remaining_path:
            # Exit node: extract destination client ID and deliver the message
            if len(inner_data) < 1:
                print(f"[Node {self.node_id} - EXIT] Message too short.")
                return
            destination_id = inner_data[0]
            message = inner_data[1:]
            print(f"[Node {self.node_id} - EXIT] Delivering message to Client {destination_id}: {message.hex()}")
            destination_client = get_client(destination_id)
            if destination_client:
                destination_client.receive_message(message)
            else:
                print(f"[Node {self.node_id} - EXIT] Destination Client {destination_id} not found.")
        else:
            # Forward to the next node
            next_node = remaining_path[0]
            new_remaining_path = remaining_path[1:]
            print(f"[Node {self.node_id}] Forwarding message to Node {next_node.node_id}")
            next_node.receive_relay(circuit_id, inner_data, new_remaining_path)

# -----------------------------
# Client Class
# -----------------------------

class Client:
    def __init__(self, client_id):
        if not (0 <= client_id <= 255):
            raise ValueError("client_id must be a single-byte integer (0-255).")
        self.client_id = client_id
        self.private_key = dh_generate_private_key()
        self.public_key = dh_generate_public_key(self.private_key)
        self.circuits = {}  # circuit_id (bytes) -> keys (list of bytes)
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
            # Generate ephemeral DH key pair for this hop
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

# -----------------------------
# Demo Execution
# -----------------------------

def main():
    # Setup nodes
    num_nodes = 5
    for i in range(num_nodes):
        node = Node(node_id=i)
        register_node(node)
    print("[Network] Registered nodes:", list(range(num_nodes)))

    # Create clients
    alice = Client(client_id=100)
    bob = Client(client_id=200)
    print(f"[Network] Registered clients: Alice (ID={alice.client_id}), Bob (ID={bob.client_id})")

    # Alice sends to Bob
    path_a_to_b, circuit_id_a_to_b, keys_a_to_b = alice.build_circuit(length=3)
    alice.send_onion_message(
        path=path_a_to_b,
        circuit_id=circuit_id_a_to_b,
        keys=keys_a_to_b,
        message=b"Hello Bob! This is Alice.",
        destination_client_id=bob.client_id
    )

    # Bob sends to Alice
    path_b_to_a, circuit_id_b_to_a, keys_b_to_a = bob.build_circuit(length=3)
    bob.send_onion_message(
        path=path_b_to_a,
        circuit_id=circuit_id_b_to_a,
        keys=keys_b_to_a,
        message=b"Hi Alice! Bob here.",
        destination_client_id=alice.client_id
    )

if __name__ == "__main__":
    main()
