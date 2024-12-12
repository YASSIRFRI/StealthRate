import os
import random

# A simple global registry of nodes to simulate the network.
# This is not a "central server," just a discovery mechanism.
NODES = {}

def register_node(node):
    NODES[node.node_id] = node

def get_node(node_id):
    return NODES.get(node_id, None)

def get_random_nodes(count):
    # Return a list of random distinct nodes from the network
    node_ids = list(NODES.keys())
    return [NODES[i] for i in random.sample(node_ids, count)]
