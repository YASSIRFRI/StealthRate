from src.node import Node
from src.network import register_node
from src.client import Client

def main():
    num_nodes = 5
    for i in range(num_nodes):
        node = Node(node_id=i)
        register_node(node)

    client = Client()

    for _ in range(3):
        path, circuit_id, keys = client.build_circuit(length=3)
        chosen_ids = [n.node_id for n in path]
        print(f"[Client] Built circuit: {chosen_ids}")
        client.send_onion_message(path, circuit_id, keys, "Hello, Anonymous World!")

if __name__ == "__main__":
    main()
