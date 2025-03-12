import random
from collections import defaultdict, deque

# Read the file and parse the nodes and links
def parse_topology(file_path):
    nodes = set()
    links = []
    
    with open(file_path, 'r') as file:
        section = None
        for line in file:
            line = line.strip()
            if not line:
                continue
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1]
                continue
            if section == 'nodes':
                node = line.split(':')[0].strip()
                nodes.add(node)
            elif section == 'links':
                parts = line.split()
                link = (parts[0].split(':')[0], parts[0].split(':')[1])
                links.append(link)
    
    return nodes, links

# Calculate the degree of each node
def calculate_degree(nodes, links):
    degree = {node: 0 for node in nodes}
    
    for link in links:
        node1, node2 = link
        degree[node1] += 1
        degree[node2] += 1

    sum = 0
    count = 0
    for node, deg in degree.items():
        sum += deg
        count += 1
    print(f"Average degree is {sum/count}")

def remove_random_edges(links, f):
    num_edges_to_remove = int(f * len(links))
    edges_to_remove = random.sample(links, num_edges_to_remove)
    
    # Create a new list of links without the removed edges
    new_links = [link for link in links if link not in edges_to_remove]
    
    return new_links, edges_to_remove

# Build adjacency list representation of the graph
def build_adjacency_list(nodes, links):
    adjacency_list = defaultdict(list)
    for node in nodes:
        adjacency_list[node] = []
    for u, v in links:
        adjacency_list[u].append(v)
        adjacency_list[v].append(u)
    return adjacency_list

# Check if the graph is connected using BFS
def is_connected(adjacency_list):
    if not adjacency_list:
        return True  # Empty graph is considered connected
    
    # Start BFS from the first node
    start_node = next(iter(adjacency_list))
    visited = set()
    queue = deque([start_node])
    
    while queue:
        node = queue.popleft()
        if node not in visited:
            visited.add(node)
            for neighbor in adjacency_list[node]:
                if neighbor not in visited:
                    queue.append(neighbor)
    
    # If all nodes are visited, the graph is connected
    return len(visited) == len(adjacency_list)

def remove_edges_preserve_connectivity(nodes, links, f):
    adjacency_list = build_adjacency_list(nodes, links)
    num_edges_to_remove = int(f * len(links))
    removed_edges = []
    
    for _ in range(num_edges_to_remove):
        # Shuffle the list of edges to randomize removal order
        random.shuffle(links)
        
        # Try removing edges one by one until a valid removal is found
        for edge in links:
            u, v = edge
            # Temporarily remove the edge
            adjacency_list[u].remove(v)
            adjacency_list[v].remove(u)
            
            # Check if the graph remains connected
            if is_connected(adjacency_list):
                # If connected, permanently remove the edge
                removed_edges.append(edge)
                links.remove(edge)
                break
            else:
                # If not connected, revert the removal
                adjacency_list[u].append(v)
                adjacency_list[v].append(u)
    
    return links, removed_edges

# Main function to read the file and calculate degrees
def main(file_path):
    nodes, links = parse_topology(file_path)
    calculate_degree(nodes, links)
    new_links, edges_to_remove = remove_edges_preserve_connectivity(nodes, links, 0.37)
    calculate_degree(nodes, new_links)
    al = build_adjacency_list(nodes, new_links)
    print(is_connected(al))
    print(edges_to_remove)
    
main('geant.conf')