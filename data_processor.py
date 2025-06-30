import pandas as pd
import json
import numpy as np
from typing import Union, Dict, List, Optional
import io
import tempfile
import os

class DataProcessor:
    """Handle data processing for intrusion detection"""
    
    def __init__(self):
        self.required_columns = [
            'Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'Label'
        ]
        self.alternative_columns = [
            ' Source IP', ' Destination IP', ' Source Port', ' Destination Port', ' Protocol', ' Label'
        ]
        
    def load_csv_file(self, file_content: bytes) -> pd.DataFrame:
        """Load CSV file from bytes content"""
        try:
            # Try different encodings
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    content = file_content.decode(encoding)
                    df = pd.read_csv(io.StringIO(content))
                    return self._validate_and_clean_dataframe(df)
                except UnicodeDecodeError:
                    continue
                    
            raise ValueError("Unable to decode file with any supported encoding")
            
        except Exception as e:
            raise ValueError(f"Error loading CSV file: {str(e)}")
            
    def load_json_file(self, file_content: bytes) -> pd.DataFrame:
        """Load JSON file from bytes content"""
        try:
            content = file_content.decode('utf-8')
            data = json.loads(content)
            
            # Handle different JSON formats
            if isinstance(data, list):
                df = pd.DataFrame(data)
            elif isinstance(data, dict) and 'data' in data:
                df = pd.DataFrame(data['data'])
            elif isinstance(data, dict) and 'flows' in data:
                df = pd.DataFrame(data['flows'])
            else:
                raise ValueError("Unsupported JSON format")
                
            return self._validate_and_clean_dataframe(df)
            
        except Exception as e:
            raise ValueError(f"Error loading JSON file: {str(e)}")
            
    def _validate_and_clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Validate and clean the dataframe"""
        # Check if required columns exist
        columns_found = []
        for col in self.required_columns:
            if col in df.columns:
                columns_found.append(col)
            elif col in self.alternative_columns:
                # Map alternative column names
                alt_col = col
                df = df.rename(columns={alt_col: col})
                columns_found.append(col)
                
        if len(columns_found) < 4:  # At least need IPs and ports
            raise ValueError(f"Missing required columns. Found: {columns_found}")
            
        # Clean column names
        df.columns = df.columns.str.strip()
        
        # Handle missing values
        df = df.fillna({
            'Source Port': 0,
            'Destination Port': 0,
            'Protocol': 6,  # Default to TCP
            'Label': 'BENIGN'
        })
        
        # Convert ports to numeric
        for col in ['Source Port', 'Destination Port']:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
                
        # Convert protocol to numeric
        if 'Protocol' in df.columns:
            df['Protocol'] = pd.to_numeric(df['Protocol'], errors='coerce').fillna(6).astype(int)
            
        return df
        
    def create_sample_data(self, num_flows: int = 100) -> pd.DataFrame:
        """Create sample network flow data for testing"""
        np.random.seed(42)
        
        # Sample IP addresses
        internal_ips = [
            '192.168.10.1', '192.168.10.10', '192.168.10.14', '192.168.10.16',
            '192.168.10.17', '192.168.10.5', '192.168.10.8', '192.168.10.9'
        ]
        
        external_ips = [
            '8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9',
            '185.167.164.39', '74.125.192.156', '23.194.142.69'
        ]
        
        data = []
        for i in range(num_flows):
            # 70% chance of benign traffic
            is_benign = np.random.random() > 0.3
            
            if is_benign:
                src_ip = np.random.choice(internal_ips)
                dst_ip = np.random.choice(external_ips)
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.choice([80, 443, 53, 22, 21])
                protocol = np.random.choice([6, 17])  # TCP or UDP
                label = 'BENIGN'
            else:
                # Malicious pattern
                src_ip = np.random.choice(internal_ips)
                dst_ip = np.random.choice(external_ips)
                src_port = np.random.randint(1024, 65535)
                dst_port = np.random.randint(1024, 42000)  # Suspicious port
                protocol = 6  # TCP
                label = 'ATTACK'
                
            data.append({
                'Source IP': src_ip,
                'Destination IP': dst_ip,
                'Source Port': src_port,
                'Destination Port': dst_port,
                'Protocol': protocol,
                'Label': label
            })
            
        return pd.DataFrame(data)
        
    def export_to_csv(self, df: pd.DataFrame) -> str:
        """Export dataframe to CSV string"""
        return df.to_csv(index=False)
        
    def export_to_json(self, df: pd.DataFrame) -> str:
        """Export dataframe to JSON string"""
        return df.to_json(orient='records', indent=2)
        
    def get_data_summary(self, df: pd.DataFrame) -> Dict:
        """Get summary statistics of the data"""
        summary = {
            'total_flows': len(df),
            'unique_source_ips': df['Source IP'].nunique() if 'Source IP' in df.columns else 0,
            'unique_destination_ips': df['Destination IP'].nunique() if 'Destination IP' in df.columns else 0,
            'protocols': df['Protocol'].value_counts().to_dict() if 'Protocol' in df.columns else {},
            'labels': df['Label'].value_counts().to_dict() if 'Label' in df.columns else {},
            'port_ranges': {
                'source_ports': {
                    'min': df['Source Port'].min() if 'Source Port' in df.columns else 0,
                    'max': df['Source Port'].max() if 'Source Port' in df.columns else 0
                },
                'destination_ports': {
                    'min': df['Destination Port'].min() if 'Destination Port' in df.columns else 0,
                    'max': df['Destination Port'].max() if 'Destination Port' in df.columns else 0
                }
            }
        }
        
        return summary 