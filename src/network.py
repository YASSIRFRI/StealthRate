# src/network.py
import random

# A simple global registry of network participants (nodes and clients).
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
    # Return a list of random distinct nodes from the network
    node_ids = list(NODES.keys())
    if count > len(node_ids):
        raise ValueError("Not enough nodes to sample the requested number.")
    return [NODES[i] for i in random.sample(node_ids, count)]
