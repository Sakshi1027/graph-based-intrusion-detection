import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool
from torch_geometric.data import Data
import networkx as nx
import pandas as pd
import numpy as np
from typing import List, Tuple, Optional
import json

class GCNModel(torch.nn.Module):
    """Graph Convolutional Network for Intrusion Detection"""
    
    def __init__(self, num_node_features: int = 2, hidden_channels: int = 8, num_classes: int = 2):
        super(GCNModel, self).__init__()
        self.conv1 = GCNConv(num_node_features, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.conv3 = GCNConv(hidden_channels, hidden_channels)
        self.lin = torch.nn.Linear(hidden_channels, num_classes)
        
    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        
        # First GCN layer
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.7, training=self.training)
        
        # Second GCN layer
        x = F.relu(self.conv2(x, edge_index))
        x = F.dropout(x, p=0.7, training=self.training)
        
        # Third GCN layer
        x = F.relu(self.conv3(x, edge_index))
        
        # Global pooling
        x = global_mean_pool(x, batch)
        
        # Final classification layer
        x = self.lin(x)
        
        return x  # Return logits, not sigmoid

class IntrusionDetector:
    """Main intrusion detection system"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = GCNModel()
        if model_path:
            self.load_model(model_path)
        self.model.eval()
        
        # Internal nodes for pattern matching
        self.internal_nodes = [
            '192.168.10.1', '192.168.10.10', '192.168.10.14', '192.168.10.16', 
            '192.168.10.17', '192.168.10.5', '192.168.10.8', '192.168.10.9', 
            '192.168.10.12', '192.168.10.15', '192.168.10.19', '192.168.10.25', 
            '192.168.10.3', '192.168.10.50', '192.168.10.51'
        ]
        
    def load_model(self, model_path: str):
        """Load trained model weights"""
        try:
            self.model.load_state_dict(torch.load(model_path, map_location='cpu'))
            print(f"Model loaded successfully from {model_path}")
        except Exception as e:
            print(f"Error loading model: {e}")
            
    def save_model(self, model_path: str):
        """Save model weights"""
        torch.save(self.model.state_dict(), model_path)
        
    def is_suspicious_port(self, port) -> bool:
        """Check if port is suspicious"""
        if port is None:
            return False
        try:
            port = int(port)
            return port > 1023 and port < 42000
        except (ValueError, TypeError):
            return False
            
    def create_graph_from_csv(self, csv_data: pd.DataFrame) -> nx.DiGraph:
        """Create NetworkX graph from CSV data"""
        graph = nx.DiGraph()
        
        for _, row in csv_data.iterrows():
            src_ip = row.get('Source IP', row.get(' Source IP', ''))
            dst_ip = row.get('Destination IP', row.get(' Destination IP', ''))
            src_port = row.get('Source Port', row.get(' Source Port', 0))
            dst_port = row.get('Destination Port', row.get(' Destination Port', 0))
            protocol = row.get('Protocol', row.get(' Protocol', 0))
            label = row.get('Label', row.get(' Label', 'BENIGN'))
            
            # Add nodes
            if not graph.has_node(src_ip):
                graph.add_node(src_ip, type='ip')
            if not graph.has_node(dst_ip):
                graph.add_node(dst_ip, type='ip')
                
            # Add edge
            graph.add_edge(src_ip, dst_ip, 
                          src_port=src_port, 
                          dst_port=dst_port, 
                          protocol=protocol, 
                          label=label)
            
        return graph
        
    def detect_malicious_patterns(self, graph: nx.DiGraph) -> List[int]:
        """Detect malicious patterns in the graph"""
        detected_patterns = []
        
        # Pattern 1: Internal host making connections to multiple external hosts on suspicious ports
        for internal_node in self.internal_nodes:
            if not graph.has_node(internal_node):
                continue
                
            outgoing_edges = graph.out_edges(internal_node, data=True)
            suspicious_external_destinations = set()
            
            for u, v, data in outgoing_edges:
                if v not in self.internal_nodes and (
                    self.is_suspicious_port(data.get('src_port')) or 
                    self.is_suspicious_port(data.get('dst_port'))
                ):
                    suspicious_external_destinations.add(v)
                    
            if len(suspicious_external_destinations) >= 2:
                detected_patterns.append(0)
                break
                
        # Pattern 2: External host making multiple connections to internal hosts
        external_nodes = [node for node in graph.nodes() if node not in self.internal_nodes]
        
        for external_node in external_nodes:
            if not graph.has_node(external_node):
                continue
                
            successors = list(graph.successors(external_node))
            internal_successors = [succ for succ in successors if succ in self.internal_nodes]
            
            if len(set(internal_successors)) >= 2:
                detected_patterns.append(1)
                break
                
        return list(set(detected_patterns))
        
    def prepare_graph_data(self, graph: nx.DiGraph) -> Data:
        """Convert NetworkX graph to PyTorch Geometric Data object"""
        # Create node features (simple degree-based features)
        node_features = []
        node_mapping = {node: idx for idx, node in enumerate(graph.nodes())}
        
        for node in graph.nodes():
            in_degree = graph.in_degree(node)
            out_degree = graph.out_degree(node)
            node_features.append([in_degree, out_degree])
            
        # Create edge index
        edge_index = []
        for u, v in graph.edges():
            edge_index.append([node_mapping[u], node_mapping[v]])
            
        # Convert to tensors
        x = torch.tensor(node_features, dtype=torch.float)
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        
        # Create batch (single graph)
        batch = torch.zeros(x.size(0), dtype=torch.long)
        
        return Data(x=x, edge_index=edge_index, batch=batch)
        
    def predict(self, csv_data: pd.DataFrame) -> dict:
        """Main prediction function"""
        try:
            # Create graph from CSV data
            graph = self.create_graph_from_csv(csv_data)
            
            # Detect patterns using graph analysis
            detected_patterns = self.detect_malicious_patterns(graph)
            
            # Prepare data for GCN
            graph_data = self.prepare_graph_data(graph)
            
            # Get GCN prediction
            with torch.no_grad():
                gcn_output = self.model(graph_data)
                # Apply softmax to get probabilities for 2 classes
                gcn_probs = torch.softmax(gcn_output, dim=1)
                # Get probability of attack class (class 1)
                gcn_probability = gcn_probs[0][1].item()
                
            # Combine pattern detection with GCN prediction
            is_attack = len(detected_patterns) > 0 or gcn_probability > 0.5
            
            return {
                'is_attack': is_attack,
                'gcn_probability': gcn_probability,
                'detected_patterns': detected_patterns,
                'graph_info': {
                    'nodes': graph.number_of_nodes(),
                    'edges': graph.number_of_edges()
                },
                'confidence': max(gcn_probability, len(detected_patterns) * 0.3)
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'is_attack': False,
                'gcn_probability': 0.0,
                'detected_patterns': [],
                'graph_info': {'nodes': 0, 'edges': 0},
                'confidence': 0.0
            } 