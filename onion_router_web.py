# onion_routing_simulation.py

import os
import random
import networkx as nx
from pyvis.network import Network
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# -----------------------------------------
# GLOBAL GRAPH AND COUNTER
# -----------------------------------------
G = nx.DiGraph()
STEP_COUNTER = 0

def visualize_network(step_description=""):
    """
    Regenerates the PyVis graph and writes it to onion_routing_simulation.html.
    We set notebook=False to avoid the 'NoneType' error on some setups.
    """
    global G, STEP_COUNTER
    STEP_COUNTER += 1

    net = Network(
        directed=True,
        height="600px",
        width="100%",
        notebook=False  # Force no Jupyter integration
    )
    net.from_nx(G)
    net.subtitle = f"Step {STEP_COUNTER}: {step_description}"

    output_file = "onion_routing_simulation.html"
    net.show(output_file,notebook=False) 
    print(f"[Visualizer] Wrote current step to '{output_file}' (step {STEP_COUNTER})")

def add_node_if_missing(node_id, label=None):
    """
    Helper to add a node if it doesn't exist.
    node_id can be int (Node) or str (Client).
    """
    if node_id not in G.nodes:
        G.add_node(node_id, label=label if label else str(node_id))

def add_edge_with_label(src, dst, label):
    """
    Adds (or updates) a directed edge from src to dst with the given label.
    Overwrites existing label if the edge already exists.
    """
    G.add_edge(src, dst, label=label)

def step_print(msg):
    print(msg)
    input("Press Enter to continue...\n")

# -----------------------------
# Cryptographic Functions
# -----------------------------
PRIME = 0xFFFFFFFB
GENERATOR = 5

def dh_generate_private_key():
    return int.from_bytes(os.urandom(32), 'big') % PRIME

def dh_generate_public_key(private_key, prime=PRIME, generator=GENERATOR):
    return pow(generator, private_key, prime)

def dh_compute_shared_secret(their_public, my_private, prime=PRIME):
    return pow(their_public, my_private, prime)

def derive_key(shared_secret):
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    return SHA256.new(secret_bytes).digest()

def aes_encrypt(key, plaintext: bytes) -> bytes:
    nonce = os.urandom(8)
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
NODES = {}
CLIENTS = {}

def register_node(node):
    """
    Registers a Node in the global dictionary and updates the PyVis graph.
    """
    NODES[node.node_id] = node
    add_node_if_missing(node.node_id, f"Node {node.node_id}")
    visualize_network(f"Register Node {node.node_id}")

def register_client(client):
    """
    Registers a Client in the global dictionary and updates the PyVis graph.
    """
    CLIENTS[client.client_id] = client
    add_node_if_missing(f"C{client.client_id}", f"Client {client.client_id}")
    visualize_network(f"Register Client {client.client_id}")

def get_node(node_id):
    return NODES.get(node_id, None)

def get_client(client_id):
    return CLIENTS.get(client_id, None)

def get_random_nodes(count):
    """
    Returns a random list of node objects from NODES.
    """
    node_ids = list(NODES.keys())
    if count > len(node_ids):
        raise ValueError("Not enough nodes to satisfy requested count.")
    return [NODES[i] for i in random.sample(node_ids, count)]

# -----------------------------
# Node Class
# -----------------------------
class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        self.circuit_keys = {}  # circuit_id -> symmetric_key

    def receive_create_circuit(self, circuit_id, their_public):
        step_print(f"[Node {self.node_id}] Handling CREATE request for circuit {circuit_id.hex()}")
        add_edge_with_label("??", self.node_id, f"CREATE {circuit_id.hex()}")

        private_key = dh_generate_private_key()
        public_key = dh_generate_public_key(private_key)
        shared_secret = dh_compute_shared_secret(their_public, private_key)
        key = derive_key(shared_secret)
        self.circuit_keys[circuit_id] = key

        step_print(f"[Node {self.node_id}] Circuit {circuit_id.hex()} created, shared key derived.")
        visualize_network(f"Node {self.node_id} CREATE done (circuit {circuit_id.hex()})")
        return public_key

    def receive_extend_circuit(self, circuit_id, next_node, next_node_pub):
        step_print(f"[Node {self.node_id}] Handling EXTEND for circuit {circuit_id.hex()} to Node {next_node.node_id}")
        add_edge_with_label(self.node_id, next_node.node_id, f"EXTEND {circuit_id.hex()}")

        their_pub = next_node.receive_create_circuit(circuit_id, next_node_pub)

        step_print(f"[Node {self.node_id}] Extension to Node {next_node.node_id} complete for circuit {circuit_id.hex()}")
        visualize_network(f"Node {self.node_id} EXTEND done (circuit {circuit_id.hex()})")
        return their_pub

    def receive_relay(self, circuit_id, data, remaining_path):
        step_print(f"[Node {self.node_id}] RELAY on circuit {circuit_id.hex()}")
        # Visual indicator of a RELAY cell coming in
        add_edge_with_label(self.node_id, self.node_id, f"RELAY {circuit_id.hex()}")

        if circuit_id not in self.circuit_keys:
            step_print(f"[Node {self.node_id}] Unknown circuit {circuit_id.hex()}, cannot decrypt.")
            return

        key = self.circuit_keys[circuit_id]
        try:
            inner_data = aes_decrypt(key, data)
            step_print(f"[Node {self.node_id}] Decrypted onion layer: {inner_data.hex()}")
        except Exception as e:
            step_print(f"[Node {self.node_id}] Decryption failed: {e}")
            return

        if not remaining_path:
            # Exit node
            if len(inner_data) < 1:
                step_print(f"[Node {self.node_id}] EXIT: message too short.")
                return
            destination_id = inner_data[0]
            message = inner_data[1:]
            step_print(f"[Node {self.node_id} - EXIT] Delivering message to Client {destination_id}")
            add_edge_with_label(self.node_id, f"C{destination_id}", f"DELIVER {circuit_id.hex()}")

            destination_client = get_client(destination_id)
            if destination_client:
                destination_client.receive_message(message)
            else:
                step_print(f"[Node {self.node_id}] Destination client {destination_id} not found.")
            visualize_network(f"Node {self.node_id} EXIT delivered message to {destination_id}")
        else:
            # Not exit, forward to next node
            next_node = remaining_path[0]
            new_remaining_path = remaining_path[1:]
            step_print(f"[Node {self.node_id}] Forwarding peeled onion to Node {next_node.node_id}")
            add_edge_with_label(self.node_id, next_node.node_id, f"FORWARD {circuit_id.hex()}")
            visualize_network(f"Node {self.node_id} RELAY forward (circuit {circuit_id.hex()})")
            next_node.receive_relay(circuit_id, inner_data, new_remaining_path)

# -----------------------------
# Client Class
# -----------------------------
class Client:
    def __init__(self, client_id):
        if not (0 <= client_id <= 255):
            raise ValueError("client_id must be [0..255]")
        self.client_id = client_id
        self.private_key = dh_generate_private_key()
        self.public_key = dh_generate_public_key(self.private_key)
        self.circuits = {}  # circuit_id -> list of symmetric keys
        register_client(self)

    def build_circuit(self, length=3):
        step_print(f"\n[Client {self.client_id}] Building circuit of length {length}...")
        path = get_random_nodes(length)
        circuit_id = os.urandom(4)

        # CREATE on the first node
        step_print(f"[Client {self.client_id}] CREATE with Node {path[0].node_id}, circuit={circuit_id.hex()}")
        add_edge_with_label(f"C{self.client_id}", path[0].node_id, f"CREATE {circuit_id.hex()}")

        priv_entry = dh_generate_private_key()
        pub_entry = dh_generate_public_key(priv_entry)
        their_pub_entry = path[0].receive_create_circuit(circuit_id, pub_entry)

        shared_secret_entry = dh_compute_shared_secret(their_pub_entry, priv_entry)
        key_entry = derive_key(shared_secret_entry)
        keys = [key_entry]

        step_print(f"[Client {self.client_id}] Key established with Node {path[0].node_id}")

        # EXTEND to subsequent nodes
        for i in range(1, length):
            step_print(f"[Client {self.client_id}] EXTEND to Node {path[i].node_id}")
            add_edge_with_label(path[0].node_id, path[i].node_id, f"EXTEND {circuit_id.hex()}")

            priv_i = dh_generate_private_key()
            pub_i = dh_generate_public_key(priv_i)
            next_node_pub = path[0].receive_extend_circuit(circuit_id, path[i], pub_i)

            shared_secret_i = dh_compute_shared_secret(next_node_pub, priv_i)
            key_i = derive_key(shared_secret_i)
            keys.append(key_i)
            step_print(f"[Client {self.client_id}] Key established with Node {path[i].node_id}")

        self.circuits[circuit_id] = keys
        chosen_ids = [node.node_id for node in path]
        step_print(f"[Client {self.client_id}] Circuit built: {circuit_id.hex()} => path: {chosen_ids}")

        visualize_network(f"Client {self.client_id} built circuit {circuit_id.hex()}")
        return path, circuit_id, keys

    def send_onion_message(self, path, circuit_id, keys, message, destination_client_id):
        step_print(f"\n[Client {self.client_id}] Sending onion message to Client {destination_client_id}")
        add_edge_with_label(f"C{self.client_id}", path[0].node_id, f"SEND {circuit_id.hex()}")

        if not (0 <= destination_client_id <= 255):
            raise ValueError("Destination client ID must be [0..255]")

        dest_id_byte = destination_client_id.to_bytes(1, 'big')
        data = dest_id_byte + message

        step_print(f"[Client {self.client_id}] Plain message hex: {data.hex()}")

        # Encrypt from exit -> entry
        for i, key in enumerate(reversed(keys)):
            data = aes_encrypt(key, data)
            step_print(f"[Client {self.client_id}] After encryption layer {i+1}: {data.hex()}")

        # Send the onion to the first node
        remaining_path = path[1:]
        first_node = path[0]
        step_print(f"[Client {self.client_id}] Handing onion to Node {first_node.node_id}")
        first_node.receive_relay(circuit_id, data, remaining_path)
        visualize_network(f"Client {self.client_id} -> Node {first_node.node_id}, onion sent")

    def receive_message(self, message):
        step_print(f"[Client {self.client_id}] Received message: {message.hex()}")
        try:
            decoded = message.decode('utf-8')
            step_print(f"[Client {self.client_id}] (UTF-8) => {decoded}")
        except UnicodeDecodeError:
            step_print(f"[Client {self.client_id}] (Binary) => {message}")

# -----------------------------
# MAIN DEMO
# -----------------------------
def main():
    step_print("[Network] Initializing...")

    # Create nodes
    num_nodes = 5
    for i in range(num_nodes):
        node = Node(node_id=i)
        register_node(node)
        step_print(f"[Network] Registered Node {i}")

    step_print("[Network] Done creating Nodes.\n")

    alice = Client(client_id=100)
    bob = Client(client_id=200)

    step_print("[Network] Clients: Alice (100), Bob (200) registered.")

    # Alice -> Bob
    path_a_to_b, circuit_id_a_to_b, keys_a_to_b = alice.build_circuit(length=3)
    # Make sure we pass in correct order (positional arguments):
    alice.send_onion_message(path_a_to_b, circuit_id_a_to_b, keys_a_to_b, b"Hello Bob! This is Alice.", bob.client_id)

    step_print("\n--- Now Bob builds a circuit and replies to Alice. ---\n")

    # Bob -> Alice
    path_b_to_a, circuit_id_b_to_a, keys_b_to_a = bob.build_circuit(length=3)
    bob.send_onion_message(path_b_to_a, circuit_id_b_to_a, keys_b_to_a, b"Hi Alice! Bob here.", alice.client_id)

    step_print("[Demo Complete] Check onion_routing_simulation.html for the final graph.")

if __name__ == "__main__":
    main()
