import matplotlib.pyplot as plt
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from typing import Dict, List, Optional
import io
from PIL import Image
import seaborn as sns

class GraphVisualizer:
    """Visualization utilities for network graphs and analysis"""
    
    def __init__(self):
        self.colors = {
            'internal': '#4ecdc4',
            'external': '#45b7d1',
            'attack': '#ff4757',
            'benign': '#2ed573',
            'suspicious': '#ffa502'
        }
        
    def create_network_graph(self, graph: nx.DiGraph, max_nodes: int = 50) -> go.Figure:
        """Create an interactive network graph visualization"""
        if len(graph.nodes()) > max_nodes:
            # Sample nodes for visualization
            nodes_to_keep = list(graph.nodes())[:max_nodes]
            graph = graph.subgraph(nodes_to_keep)
            
        # Get node positions using spring layout
        pos = nx.spring_layout(graph, k=1, iterations=50)
        
        # Prepare node data
        node_x = []
        node_y = []
        node_text = []
        node_color = []
        
        for node in graph.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            # Determine node type and color
            if '192.168.10.' in str(node):
                node_type = 'Internal'
                color = self.colors['internal']
            else:
                node_type = 'External'
                color = self.colors['external']
                
            node_text.append(f"{node}<br>Type: {node_type}<br>Degree: {graph.degree(node)}")
            node_color.append(color)
            
        # Prepare edge data
        edge_x = []
        edge_y = []
        edge_color = []
        
        for edge in graph.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
            # Color edges based on suspicious ports
            if edge[2].get('src_port', 0) > 1023 and edge[2].get('src_port', 0) < 42000:
                edge_color.extend(['#ffa502', '#ffa502', None])  # Suspicious
            else:
                edge_color.extend(['#95a5a6', '#95a5a6', None])  # Normal
                
        # Create the figure
        fig = go.Figure()
        
        # Add edges
        fig.add_trace(go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#95a5a6'),
            hoverinfo='none',
            mode='lines',
            showlegend=False
        ))
        
        # Add nodes
        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=[node.split('.')[-1] for node in graph.nodes()],  # Show last octet
            textposition="middle center",
            textfont=dict(size=8, color='white'),
            marker=dict(
                size=20,
                color=node_color,
                line=dict(width=2, color='white')
            ),
            showlegend=False
        ))
        
        # Update layout
        fig.update_layout(
            title='Network Graph Visualization',
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='white'
        )
        
        return fig
        
    def create_attack_analysis_chart(self, prediction_result: Dict) -> go.Figure:
        """Create analysis chart for attack detection results"""
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Detection Confidence', 'Pattern Analysis', 'Graph Statistics', 'Risk Assessment'),
            specs=[[{"type": "indicator"}, {"type": "bar"}],
                   [{"type": "bar"}, {"type": "indicator"}]]
        )
        
        # Confidence indicator
        confidence = prediction_result.get('confidence', 0)
        fig.add_trace(
            go.Indicator(
                mode="gauge+number+delta",
                value=confidence * 100,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Detection Confidence (%)"},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 30], 'color': "lightgray"},
                        {'range': [30, 70], 'color': "yellow"},
                        {'range': [70, 100], 'color': "red"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 70
                    }
                }
            ),
            row=1, col=1
        )
        
        # Pattern analysis
        patterns = prediction_result.get('detected_patterns', [])
        pattern_names = ['Internal to External', 'External to Internal']
        pattern_values = [1 if i in patterns else 0 for i in range(2)]
        
        fig.add_trace(
            go.Bar(
                x=pattern_names,
                y=pattern_values,
                marker_color=['red' if v == 1 else 'green' for v in pattern_values],
                name='Detected Patterns'
            ),
            row=1, col=2
        )
        
        # Graph statistics
        graph_info = prediction_result.get('graph_info', {})
        stats_names = ['Nodes', 'Edges']
        stats_values = [graph_info.get('nodes', 0), graph_info.get('edges', 0)]
        
        fig.add_trace(
            go.Bar(
                x=stats_names,
                y=stats_values,
                marker_color='blue',
                name='Graph Statistics'
            ),
            row=2, col=1
        )
        
        # Risk assessment
        is_attack = prediction_result.get('is_attack', False)
        risk_level = "HIGH" if is_attack else "LOW"
        risk_color = "red" if is_attack else "green"
        
        fig.add_trace(
            go.Indicator(
                mode="number+delta",
                value=1 if is_attack else 0,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': f"Risk Level: {risk_level}"},
                delta={'reference': 0},
                number={'font': {'color': risk_color}}
            ),
            row=2, col=2
        )
        
        fig.update_layout(height=600, showlegend=False)
        return fig
        
    def create_data_summary_chart(self, data_summary: Dict) -> go.Figure:
        """Create summary charts for uploaded data"""
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Protocol Distribution', 'Label Distribution', 'Port Ranges', 'IP Distribution'),
            specs=[[{"type": "pie"}, {"type": "pie"}],
                   [{"type": "bar"}, {"type": "bar"}]]
        )
        
        # Protocol distribution
        protocols = data_summary.get('protocols', {})
        if protocols:
            fig.add_trace(
                go.Pie(
                    labels=list(protocols.keys()),
                    values=list(protocols.values()),
                    name="Protocols"
                ),
                row=1, col=1
            )
            
        # Label distribution
        labels = data_summary.get('labels', {})
        if labels:
            fig.add_trace(
                go.Pie(
                    labels=list(labels.keys()),
                    values=list(labels.values()),
                    name="Labels"
                ),
                row=1, col=2
            )
            
        # Port ranges
        port_ranges = data_summary.get('port_ranges', {})
        if port_ranges:
            source_ports = [port_ranges['source_ports']['min'], port_ranges['source_ports']['max']]
            dest_ports = [port_ranges['destination_ports']['min'], port_ranges['destination_ports']['max']]
            
            fig.add_trace(
                go.Bar(
                    x=['Source Min', 'Source Max', 'Dest Min', 'Dest Max'],
                    y=source_ports + dest_ports,
                    name='Port Ranges'
                ),
                row=2, col=1
            )
            
        # IP distribution
        fig.add_trace(
            go.Bar(
                x=['Source IPs', 'Destination IPs'],
                y=[data_summary.get('unique_source_ips', 0), data_summary.get('unique_destination_ips', 0)],
                name='IP Distribution'
            ),
            row=2, col=2
        )
        
        fig.update_layout(height=600, showlegend=False)
        return fig
        
    def create_matplotlib_graph(self, graph: nx.DiGraph, max_nodes: int = 30) -> Image.Image:
        """Create a static matplotlib graph image"""
        if len(graph.nodes()) > max_nodes:
            nodes_to_keep = list(graph.nodes())[:max_nodes]
            graph = graph.subgraph(nodes_to_keep)
            
        plt.figure(figsize=(12, 8))
        
        # Use spring layout
        pos = nx.spring_layout(graph, k=2, iterations=50)
        
        # Draw nodes
        internal_nodes = [n for n in graph.nodes() if '192.168.10.' in str(n)]
        external_nodes = [n for n in graph.nodes() if n not in internal_nodes]
        
        nx.draw_networkx_nodes(graph, pos, nodelist=internal_nodes, 
                              node_color=self.colors['internal'], node_size=500, alpha=0.8)
        nx.draw_networkx_nodes(graph, pos, nodelist=external_nodes, 
                              node_color=self.colors['external'], node_size=500, alpha=0.8)
        
        # Draw edges
        nx.draw_networkx_edges(graph, pos, edge_color='gray', arrows=True, arrowsize=10)
        
        # Draw labels (only for internal nodes to avoid clutter)
        labels = {node: node.split('.')[-1] for node in internal_nodes}
        nx.draw_networkx_labels(graph, pos, labels, font_size=8, font_color='white')
        
        plt.title('Network Graph Analysis', fontsize=16, fontweight='bold')
        plt.axis('off')
        
        # Save to PIL Image
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
        buf.seek(0)
        img = Image.open(buf)
        plt.close()
        
        return img
        
    def create_timeline_chart(self, data: pd.DataFrame) -> go.Figure:
        """Create timeline chart for network flows"""
        if 'Timestamp' not in data.columns:
            # Create dummy timeline if no timestamp
            data = data.copy()
            data['Timestamp'] = pd.date_range(start='2024-01-01', periods=len(data), freq='1min')
            
        # Convert timestamp to datetime if needed
        data['Timestamp'] = pd.to_datetime(data['Timestamp'])
        
        # Group by time and count flows
        timeline_data = data.groupby(data['Timestamp'].dt.floor('5min')).size().reset_index()
        timeline_data.columns = ['timestamp', 'flow_count']
        
        # Create timeline
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=timeline_data['timestamp'],
            y=timeline_data['flow_count'],
            mode='lines+markers',
            name='Network Flows',
            line=dict(color='blue', width=2),
            marker=dict(size=6)
        ))
        
        fig.update_layout(
            title='Network Flow Timeline',
            xaxis_title='Time',
            yaxis_title='Number of Flows',
            hovermode='x unified'
        )
        
        return fig

    def create_data_summary_charts(self, df: pd.DataFrame):
        # Top source IPs
        if 'Source IP' in df.columns:
            top_sources = df['Source IP'].value_counts().head(10)
            fig1 = go.Figure(data=[go.Bar(
                x=top_sources.values,
                y=top_sources.index,
                orientation='h',
                marker_color='#3742fa'
            )])
            fig1.update_layout(
                title='Top 10 Source IPs',
                xaxis_title='Number of Flows',
                height=400
            )
        else:
            fig1 = self._create_empty_chart("No source IP data")

        # Top destination IPs
        if 'Destination IP' in df.columns:
            top_destinations = df['Destination IP'].value_counts().head(10)
            fig2 = go.Figure(data=[go.Bar(
                x=top_destinations.values,
                y=top_destinations.index,
                orientation='h',
                marker_color='#ffa502'
            )])
            fig2.update_layout(
                title='Top 10 Destination IPs',
                xaxis_title='Number of Flows',
                height=400
            )
        else:
            fig2 = self._create_empty_chart("No destination IP data")

        return fig1, fig2