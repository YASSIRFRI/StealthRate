# run_demo.py
from src.node import Node
from src.network import register_node
from src.client import Client

def main():
    # Setup a network of nodes
    num_nodes = 5
    for i in range(num_nodes):
        node = Node(node_id=i)
        register_node(node)
    print("[Network] Registered nodes:", list(range(num_nodes)))

    # Create two clients: Alice (ID=100) and Bob (ID=200)
    alice = Client(client_id=100)
    bob = Client(client_id=200)
    print(f"[Network] Registered clients: Alice (ID={alice.client_id}), Bob (ID={bob.client_id})")

    # Alice sends a message to Bob
    path_a_to_b, circuit_id_a_to_b, keys_a_to_b = alice.build_circuit(length=3)
    alice.send_onion_message(
        path=path_a_to_b,
        circuit_id=circuit_id_a_to_b,
        keys=keys_a_to_b,
        message="Hello Bob! This is Alice.",
        destination_client_id=bob.client_id
    )

    # Bob sends a message to Alice
    path_b_to_a, circuit_id_b_to_a, keys_b_to_a = bob.build_circuit(length=3)
    bob.send_onion_message(
        path=path_b_to_a,
        circuit_id=circuit_id_b_to_a,
        keys=keys_b_to_a,
        message="Hi Alice! Bob here.",
        destination_client_id=alice.client_id
    )

if __name__ == "__main__":
    main()
