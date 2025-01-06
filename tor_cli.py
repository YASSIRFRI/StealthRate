import os
import random
import sys
import tempfile
import shlex
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from dataclasses import dataclass, asdict
import threading
import time

PRIME = 0xFFFFFFFB  # A large prime number equal to 4294967291
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

NODES = {}
CLIENTS = {}
CLIENT_ID_COUNTER = 1 

def register_node(node):
    NODES[node.node_id] = node

def register_client(client):
    CLIENTS[client.name.lower()] = client

def get_node(node_id):
    return NODES.get(node_id, None)

def get_client(client_name):
    return CLIENTS.get(client_name.lower(), None)

def get_random_nodes(count):
    node_ids = list(NODES.keys())
    if count > len(node_ids):
        raise ValueError("Not enough nodes to sample the requested number.")
    return [NODES[i] for i in random.sample(node_ids, count)]


CLASS_STUDENTS = [
    "Omar", "Ayman", "Amine", "Ziko", "Ilyas",
    "Rachid", "Hassan", "Omar", "Soufiane", "Adnan",
    "Fatima", "Aicha", "Khadija", "Leila", "Zineb",
    "Meryem", "Nadia", "Salma", "Imane", "Sara"
]

class Node:
    def __init__(self, node_id, name):
        self.node_id = node_id
        self.name = name
        self.circuit_keys = {}
    
    def receive_create_circuit(self, circuit_id, their_public):
        """
        Handle a CREATE request: perform DH to establish a shared key 
        for this circuit at this node.
        """
        private_key = dh_generate_private_key()
        public_key = dh_generate_public_key(private_key)
        shared_secret = dh_compute_shared_secret(their_public, private_key)
        key = derive_key(shared_secret)
        self.circuit_keys[circuit_id] = key
        print(f"[Node {self.name} (ID: {self.node_id})] Created circuit {circuit_id.hex()} and derived a shared key.")
        return public_key
    
    def receive_extend_circuit(self, circuit_id, next_node, next_node_pub):
        """
        The client instructs THIS node to extend the circuit to 'next_node'.
        We do a CREATE handshake with 'next_node' on behalf of the client.
        
        next_node_pub = ephemeral public key from the client for the new hop.
        We call next_node.receive_create_circuit(...) to complete the handshake 
        and get back next_node's ephemeral public key, which we then return 
        to the client (through the calling function).
        """
        print(f"[Node {self.name} (ID: {self.node_id})] Extending circuit {circuit_id.hex()} to Node {next_node.name} (ID: {next_node.node_id}).")
        their_pub = next_node.receive_create_circuit(circuit_id, next_node_pub)
        return their_pub
    
    def receive_relay(self, circuit_id, data, remaining_path, message_type):
        """
        Receive an onion-wrapped message:
        - Decrypt one layer using the circuit key.
        - If remaining_path is empty, we're the exit node and handle the message.
        - Otherwise, forward the peeled onion to the next node in the path.
        """
        if circuit_id not in self.circuit_keys:
            print(f"[Node {self.name} (ID: {self.node_id})] Unknown circuit {circuit_id.hex()}.")
            return

        key = self.circuit_keys[circuit_id]
        try:
            inner_data = aes_decrypt(key, data)
        except Exception as e:
            print(f"[Node {self.name} (ID: {self.node_id})] Decryption failed for circuit {circuit_id.hex()}: {e}")
            return
        print(f"[Node {self.name} (ID: {self.node_id})] Decrypted layer: {inner_data.hex()}")
        if not remaining_path:
            if message_type == "message":
                if len(inner_data) < 1:
                    print(f"[Node {self.name} (ID: {self.node_id}) - EXIT] Message too short.")
                    return
                destination_id = inner_data[0]
                message = inner_data[1:]
                print(f"[Node {self.name} (ID: {self.node_id}) - EXIT] Delivering message to Client ID {destination_id}: {message.hex()}")
                destination_client = get_client_id(destination_id)
                if destination_client:
                    destination_client.receive_message(message)
                else:
                    print(f"[Node {self.name} (ID: {self.node_id}) - EXIT] Destination Client ID {destination_id} not found.")
            elif message_type == "rating":
                rating_text = inner_data.decode('utf-8', errors='ignore')
                print(f"[Node {self.name} (ID: {self.node_id}) - EXIT] Received rating: {rating_text}")
                flush_rating(rating_text)
            else:
                print(f"[Node {self.name} (ID: {self.node_id}) - EXIT] Unknown message type.")
        else:
            next_node = remaining_path[0]
            new_remaining_path = remaining_path[1:]
            print(f"[Node {self.name} (ID: {self.node_id})] Forwarding message to Node {next_node.name} (ID: {next_node.node_id})")
            next_node.receive_relay(circuit_id, inner_data, new_remaining_path, message_type)


class Client:
    def __init__(self, client_id, name, message_dir):
        if not (1 <= client_id <= 255):
            raise ValueError("client_id must be a single-byte integer (1-255).")
        self.client_id = client_id
        self.name = name
        self.private_key = dh_generate_private_key()
        self.public_key = dh_generate_public_key(self.private_key)
        self.circuits = {}
        register_client(self)
        self.message_file = os.path.join(message_dir, f"{self.name}_messages.tmp")
        with open(self.message_file, 'w', encoding='utf-8') as f:
            pass 
    
    def build_circuit(self, length=3):
        """
        Build a circuit in an incremental (Tor-like) way:
          1) Pick a path of nodes.
          2) CREATE the first node, do DH with it to get key_0.
          3) EXTEND through the first node to the second node, do DH for key_1.
          4) EXTEND again for key_2, etc.
        
        Returns:
            path:       list of nodes (entry -> ... -> exit)
            circuit_id: unique circuit identifier (bytes)
            keys:       list of symmetric keys for each hop
        """
        print(f"\n[Client {self.name}] Building circuit incrementally...")
        path = get_random_nodes(length)
        circuit_id = os.urandom(4)

        keys = []
        priv = dh_generate_private_key()
        pub = dh_generate_public_key(priv)
        their_pub = path[0].receive_create_circuit(circuit_id, pub)
        shared_secret = dh_compute_shared_secret(their_pub, priv)
        key = derive_key(shared_secret)
        keys.append(key)
        print(f"[Client {self.name}] Established key with Node {path[0].name} (ID: {path[0].node_id}) for circuit {circuit_id.hex()}")

        for i in range(1, length):
            priv = dh_generate_private_key()
            pub = dh_generate_public_key(priv)
            their_pub = path[i].receive_create_circuit(circuit_id, pub)
            shared_secret = dh_compute_shared_secret(their_pub, priv)
            key = derive_key(shared_secret)
            keys.append(key)
            print(f"[Client {self.name}] Established key with Node {path[i].name} (ID: {path[i].node_id}) for circuit {circuit_id.hex()}")

        self.circuits[circuit_id] = {
            'path': path,
            'keys': keys
        }
        chosen_names = [node.name for node in path]
        print(f"[Client {self.name}] Built circuit through Nodes: {chosen_names}")
        return path, circuit_id, keys
    
    def send_onion_message(self, circuit_id, message, destination_client_id):
        """
        Onion-encrypt the message using the keys in reverse order and send it.
        """
        circuit = self.circuits.get(circuit_id, None)
        if not circuit:
            print(f"[Client {self.name}] No such circuit {circuit_id.hex()}.")
            return

        path = circuit['path']
        keys = circuit['keys']
        
        if not path:
            print(f"[Client {self.name}] Circuit path is empty.")
            return

        if not (1 <= destination_client_id <= 255):
            raise ValueError("Destination client ID must be a single-byte integer (1-255).")

        dest_id_byte = destination_client_id.to_bytes(1, 'big')
        message_bytes = message.encode('utf-8')
        data = dest_id_byte + message_bytes
        print(f"\n[Client {self.name}] Sending message: {data.hex()} to Client ID {destination_client_id}")

        for i, key in enumerate(reversed(keys)):
            data = aes_encrypt(key, data)
            print(f"[Client {self.name}] After encryption layer {i+1}: {data.hex()}")

        remaining_path = path[1:]
        first_node = path[0]
        print(f"[Client {self.name}] Sending onion to Node {first_node.name} (ID: {first_node.node_id})")
        first_node.receive_relay(circuit_id, data, remaining_path, "message")
    
    def submit_rating(self, circuit_id, rating_text):
        """
        Onion-encrypt the rating text and send it to the exit node to be flushed to ratings.txt.
        """
        circuit = self.circuits.get(circuit_id, None)
        if not circuit:
            print(f"[Client {self.name}] No such circuit {circuit_id.hex()}.")
            return

        path = circuit['path']
        keys = circuit['keys']
        
        if not path:
            print(f"[Client {self.name}] Circuit path is empty.")
            return

        message_bytes = rating_text.encode('utf-8')
        data = message_bytes
        print(f"\n[Client {self.name}] Submitting rating: {message_bytes.hex()}")

        for i, key in enumerate(reversed(keys)):
            data = aes_encrypt(key, data)
            print(f"[Client {self.name}] After encryption layer {i+1}: {data.hex()}")

        remaining_path = path[1:]
        first_node = path[0]
        print(f"[Client {self.name}] Sending rating to Node {first_node.name} (ID: {first_node.node_id})")
        first_node.receive_relay(circuit_id, data, remaining_path, "rating")
    
    def receive_message(self, message):
        """
        Decode and store the received message.
        """
        try:
            message_str = message.decode('utf-8')
            with open(self.message_file, 'a', encoding='utf-8') as f:
                f.write(f"Received message: {message_str}\n")
            print(f"[Client {self.name}] Received message: {message_str}")
        except UnicodeDecodeError:
            with open(self.message_file, 'a') as f:
                f.write(f"Received binary message: {message.hex()}\n")
            print(f"[Client {self.name}] Received binary message: {message.hex()}")
    
    def show_messages(self):
        """
        Display all received messages.
        """
        print(f"\n[Client {self.name}] Showing received messages:")
        if os.path.exists(self.message_file):
            with open(self.message_file, 'r', encoding='utf-8') as f:
                content = f.read()
                print(content if content else "No messages received.")
        else:
            print("No messages received.")

    def draw_circuit(self, circuit_id):
        """
        Display the circuit details in the command line.
        """
        circuit = self.circuits.get(circuit_id, None)
        if not circuit:
            print(f"[Client {self.name}] No such circuit {circuit_id.hex()}.")
            return

        path = circuit['path']
        keys = circuit['keys']

        print(f"\n[Client {self.name}] Drawing Circuit {circuit_id.hex()}:")
        print(f"Source: {self.name} (Client ID: {self.client_id})")
        for i, node in enumerate(path):
            print(f"Hop {i+1}: {node.name} (ID: {node.node_id})")
            print(f"  - Generator: {GENERATOR}")
            print(f"  - Symmetric Key {i+1}: {keys[i].hex()}")
            if i < len(path) - 1:
                print("      ↓")
        print(f"Exit Node: {path[-1].name} (ID: {path[-1].node_id})")
        print(f"End of Circuit {circuit_id.hex()}\n")


def flush_rating(rating_text):
    """
    Flush the rating to ratings.txt
    """
    try:
        with open("ratings.txt", 'a', encoding='utf-8') as f:
            f.write(f"{rating_text}\n")
        print(f"[System] Rating flushed to ratings.txt: {rating_text}")
    except Exception as e:
        print(f"[System] Failed to flush rating: {e}")


def get_client_id(client_id):
    for client in CLIENTS.values():
        if client.client_id == client_id:
            return client
    return None


class OnionRoutingCLI:
    def __init__(self):
        self.current_client = None
        self.message_dir = tempfile.mkdtemp(prefix="onion_routing_messages_")
        self.initialize_network()
        self.assigned_node_names = set()
    
    def initialize_network(self):
        num_nodes = 5
        available_names = CLASS_STUDENTS.copy()
        if len(available_names) < num_nodes:
            raise ValueError("Not enough Moroccan names to assign to nodes.")
        selected_names = random.sample(available_names, num_nodes)
        for i in range(num_nodes):
            node = Node(node_id=i, name=selected_names[i])
            register_node(node)
        print("[Network] Registered Nodes:")
        for node in NODES.values():
            print(f"  - {node.name} (ID: {node.node_id})")
    
    def start(self):
        print("\nWelcome to the Onion Routing CLI!")
        print("Type 'help' to see available commands.\n")
        while True:
            try:
                user_input = input("onion-routing> ")
                if not user_input.strip():
                    continue
                args = shlex.split(user_input)
                command = args[0].lower()
                getattr(self, f"cmd_{command}", self.cmd_unknown)(args[1:])
            except (EOFError, KeyboardInterrupt):
                print("\nExiting Onion Routing CLI.")
                self.cleanup()
                sys.exit(0)
            except Exception as e:
                print(f"Error: {e}")
    
    def cmd_help(self, args):
        help_text = """
Available Commands:
  login <name>                        : Login as a client (any unique name).
  logout                              : Logout the current client.
  build                               : Build a new circuit for the logged-in client.
  send "<message>" to <name>          : Send a message to another client.
  submit rating "<rating text>"       : Submit an anonymous course rating.
  show messages                       : Show received messages for the logged-in client.
  draw circuit <circuit_id>           : Draw the specified circuit with detailed information.
  exit                                : Exit the CLI.
  help                                : Show this help message.
"""
        print(help_text)
    
    def cmd_login(self, args):
        if self.current_client:
            print(f"Already logged in as {self.current_client.name}. Please logout first.")
            return
        if len(args) != 1:
            print("Usage: login <name>")
            return
        name = args[0].lower()
        client = get_client(name)
        if not client:
            global CLIENT_ID_COUNTER
            if CLIENT_ID_COUNTER > 255:
                print("Maximum number of clients reached.")
                return
            client = Client(client_id=CLIENT_ID_COUNTER, name=name, message_dir=self.message_dir)
            CLIENT_ID_COUNTER += 1
            print(f"Registered new client: {client.name} (ID: {client.client_id})")
        self.current_client = client
        print(f"Logged in as {self.current_client.name} (Client ID: {self.current_client.client_id}).")
    
    def cmd_logout(self, args):
        if not self.current_client:
            print("No client is currently logged in.")
            return
        print(f"Logged out from {self.current_client.name}.")
        self.current_client = None
    
    def cmd_build(self, args):
        if not self.current_client:
            print("Please login as a client first.")
            return
        circuit_info = self.current_client.build_circuit(length=3)
        circuit_id = circuit_info[1]
        print(f"Circuit {circuit_id.hex()} built successfully.")
    
    def cmd_send(self, args):
        if not self.current_client:
            print("Please login as a client first.")
            return
        if len(args) < 3:
            print('Usage: send "<message>" to <name>')
            return
        if args[-2].lower() != 'to':
            print('Usage: send "<message>" to <name>')
            return
        message = args[0]
        recipient_name = args[-1].lower()
        recipient = get_client(recipient_name)
        if not recipient:
            print(f"Recipient '{recipient_name}' does not exist. Please ensure they are registered.")
            return
        if not self.current_client.circuits:
            print("No circuits available. Please build a circuit first.")
            return
        circuit_id = next(iter(self.current_client.circuits))
        try:
            self.current_client.send_onion_message(circuit_id, message, recipient.client_id)
            print("Message sent successfully.")
        except Exception as e:
            print(f"Failed to send message: {e}")
    
    def cmd_submit(self, args):
        if not self.current_client:
            print("Please login as a client first.")
            return
        if len(args) < 2 or args[0].lower() != 'rating':
            print('Usage: submit rating "<rating text>"')
            return
        rating_text = args[1]
        if not self.current_client.circuits:
            print("No circuits available. Please build a circuit first.")
            return
        circuit_id = next(iter(self.current_client.circuits))
        try:
            self.current_client.submit_rating(circuit_id, rating_text)
            print("Rating submitted successfully.")
        except Exception as e:
            print(f"Failed to submit rating: {e}")
    
    def cmd_show(self, args):
        if not self.current_client:
            print("Please login as a client first.")
            return
        if len(args) != 1 or args[0].lower() != 'messages':
            print("Usage: show messages")
            return
        self.current_client.show_messages()
    
    def cmd_draw(self, args):
        if not self.current_client:
            print("Please login as a client first.")
            return
        if len(args) != 2 or args[0].lower() != 'circuit':
            print("Usage: draw circuit <circuit_id>")
            return
        circuit_id_hex = args[1]
        try:
            circuit_id = bytes.fromhex(circuit_id_hex)
        except ValueError:
            print("Invalid circuit_id format. It should be a hexadecimal string.")
            return
        self.current_client.draw_circuit(circuit_id)
    
    def cmd_exit(self, args):
        print("Exiting Onion Routing CLI.")
        self.cleanup()
        sys.exit(0)
    
    def cmd_unknown(self, args):
        print("Unknown command. Type 'help' to see available commands.")
    
    def cleanup(self):
        if os.path.exists(self.message_dir):
            for filename in os.listdir(self.message_dir):
                file_path = os.path.join(self.message_dir, filename)
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"Failed to delete {file_path}: {e}")
            try:
                os.rmdir(self.message_dir)
            except Exception as e:
                print(f"Failed to remove message directory: {e}")

# -----------------------------
#cli
# -----------------------------

def main():
    cli = OnionRoutingCLI()
    cli.start()

if __name__ == "__main__":
    main()
