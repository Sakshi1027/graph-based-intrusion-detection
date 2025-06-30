import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from PIL import Image
import io
import sys
import os

# Add the current directory to path to import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gcn_model import IntrusionDetector
from data_processor import DataProcessor
from visualizer import GraphVisualizer

# Page configuration
st.set_page_config(
    page_title="Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        background: linear-gradient(90deg, #ff6b6b, #4ecdc4);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    
    .attack-alert {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        animation: pulse 2s infinite;
    }
    
    .benign-alert {
        background: linear-gradient(135deg, #2ed573 0%, #1e90ff 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'detector' not in st.session_state:
    st.session_state.detector = IntrusionDetector('gcn_model_weights.pth')
if 'data_processor' not in st.session_state:
    st.session_state.data_processor = DataProcessor()
if 'visualizer' not in st.session_state:
    st.session_state.visualizer = GraphVisualizer()

def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ Network Intrusion Detection System</h1>', unsafe_allow_html=True)
    st.markdown("### Graph-Based Intrusion Detection using GCN and Pattern Matching")
    
    # Sidebar
    with st.sidebar:
        st.header("📊 Navigation")
        page = st.selectbox(
            "Choose a page:",
            ["🏠 Home", "📁 Upload & Analyze", "📈 Visualizations", "⚙️ Settings", "ℹ️ About"]
        )
        
        st.markdown("---")
        st.markdown("### 🔧 Quick Actions")
        if st.button("🔄 Reset Session"):
            st.session_state.clear()
            st.rerun()
            
        if st.button("📊 Generate Sample Data"):
            sample_data = st.session_state.data_processor.create_sample_data(100)
            st.session_state.current_data = sample_data
            st.success("Sample data generated!")
    
    # Page routing
    if page == "🏠 Home":
        show_home_page()
    elif page == "📁 Upload & Analyze":
        show_upload_analyze_page()
    elif page == "📈 Visualizations":
        show_visualizations_page()
    elif page == "⚙️ Settings":
        show_settings_page()
    elif page == "ℹ️ About":
        show_about_page()

def show_home_page():
    """Home page with overview and quick stats"""
    st.markdown("## 🎯 Welcome to the Network Intrusion Detection System")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h3>🔍 Detection Methods</h3>
            <p>• Graph Pattern Matching</p>
            <p>• GCN Neural Network</p>
            <p>• Incremental Analysis</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h3>📊 Supported Formats</h3>
            <p>• CSV Files</p>
            <p>• JSON Files</p>
            <p>• Network Flow Data</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h3>⚡ Performance</h3>
            <p>• Real-time Analysis</p>
            <p>• High Accuracy</p>
            <p>• Low Latency</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Quick start guide
    st.markdown("## 🚀 Quick Start Guide")
    
    st.markdown("""
    1. **Upload Data**: Go to the "Upload & Analyze" page
    2. **Choose File**: Upload your CSV or JSON network flow data
    3. **Analyze**: Click "Analyze Network" to run intrusion detection
    4. **View Results**: Check the detection results and visualizations
    5. **Explore**: Use the visualizations page for detailed analysis
    """)
    
    # System status
    st.markdown("## 🔧 System Status")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.session_state.detector.model is not None:
            st.success("✅ GCN Model Loaded")
        else:
            st.error("❌ GCN Model Not Loaded")
    
    with col2:
        if 'current_data' in st.session_state:
            st.success(f"✅ Data Loaded ({len(st.session_state.current_data)} flows)")
        else:
            st.warning("⚠️ No Data Loaded")

def show_upload_analyze_page():
    """Upload and analyze page"""
    st.markdown("## 📁 Upload & Analyze Network Data")
    
    # File upload section
    st.markdown("### 📤 Upload Network Flow Data")
    
    uploaded_file = st.file_uploader(
        "Choose a CSV or JSON file",
        type=['csv', 'json'],
        help="Upload network flow data with columns: Source IP, Destination IP, Source Port, Destination Port, Protocol, Label"
    )
    
    # Or use sample data
    use_sample = st.checkbox("Use sample data for testing")
    
    if uploaded_file is not None or use_sample:
        try:
            with st.spinner("Processing data..."):
                if uploaded_file is not None:
                    file_content = uploaded_file.read()
                    if uploaded_file.name.endswith('.csv'):
                        data = st.session_state.data_processor.load_csv_file(file_content)
                    else:
                        data = st.session_state.data_processor.load_json_file(file_content)
                else:
                    data = st.session_state.data_processor.create_sample_data(100)
                
                st.session_state.current_data = data
                st.success(f"✅ Data loaded successfully! {len(data)} network flows detected.")
                
                # Show data summary
                summary = st.session_state.data_processor.get_data_summary(data)
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Flows", summary['total_flows'])
                with col2:
                    st.metric("Source IPs", summary['unique_source_ips'])
                with col3:
                    st.metric("Destination IPs", summary['unique_destination_ips'])
                with col4:
                    st.metric("Protocols", len(summary['protocols']))
                
        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")
            return
    
    # Analysis section
    if 'current_data' in st.session_state:
        st.markdown("### 🔍 Network Analysis")
        
        if st.button("🚀 Run Intrusion Detection Analysis", type="primary"):
            with st.spinner("Running intrusion detection analysis..."):
                try:
                    # Run prediction
                    result = st.session_state.detector.predict(st.session_state.current_data)
                    st.session_state.last_result = result
                    
                    # Display results
                    st.markdown("### 📊 Analysis Results")
                    
                    if result.get('error'):
                        st.error(f"❌ Analysis Error: {result['error']}")
                        return
                    
                    # Create result display
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if result['is_attack']:
                            st.markdown("""
                            <div class="attack-alert">
                                <h2>🚨 ATTACK DETECTED</h2>
                                <p>Malicious activity identified in the network</p>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown("""
                            <div class="benign-alert">
                                <h2>✅ BENIGN TRAFFIC</h2>
                                <p>No malicious activity detected</p>
                            </div>
                            """, unsafe_allow_html=True)
                    
                    with col2:
                        st.metric("Confidence", f"{result['confidence']:.2%}")
                        st.metric("GCN Probability", f"{result['gcn_probability']:.2%}")
                        st.metric("Detected Patterns", len(result['detected_patterns']))
                        st.metric("Graph Nodes", result['graph_info']['nodes'])
                        st.metric("Graph Edges", result['graph_info']['edges'])
                    
                    # Pattern details
                    if result['detected_patterns']:
                        st.markdown("### 🎯 Detected Patterns")
                        pattern_descriptions = {
                            0: "Internal host making connections to multiple external hosts on suspicious ports",
                            1: "External host making multiple connections to internal hosts"
                        }
                        
                        for pattern in result['detected_patterns']:
                            st.warning(f"**Pattern {pattern}**: {pattern_descriptions.get(pattern, 'Unknown pattern')}")
                    
                    st.success("✅ Analysis completed successfully!")
                    
                except Exception as e:
                    st.error(f"❌ Error during analysis: {str(e)}")

def show_visualizations_page():
    """Visualizations page"""
    st.markdown("## 📈 Data Visualizations")
    
    if 'current_data' not in st.session_state:
        st.warning("⚠️ Please upload data first to see visualizations.")
        return
    
    data = st.session_state.current_data
    
    # Data summary charts
    st.markdown("### 📊 Data Summary")
    summary = st.session_state.data_processor.get_data_summary(data)
    
    # Create summary chart
    fig = st.session_state.visualizer.create_data_summary_chart(summary)
    st.plotly_chart(fig, use_container_width=True)
    
    # Timeline chart
    st.markdown("### ⏰ Network Flow Timeline")
    timeline_fig = st.session_state.visualizer.create_timeline_chart(data)
    st.plotly_chart(timeline_fig, use_container_width=True)
    
    # Network graph visualization
    if 'last_result' in st.session_state:
        st.markdown("### 🕸️ Network Graph Analysis")
        
        # Create graph from data
        graph = st.session_state.detector.create_graph_from_csv(data)
        
        # Interactive network graph
        network_fig = st.session_state.visualizer.create_network_graph(graph)
        st.plotly_chart(network_fig, use_container_width=True)
        
        # Attack analysis chart
        st.markdown("### 🎯 Attack Analysis")
        analysis_fig = st.session_state.visualizer.create_attack_analysis_chart(st.session_state.last_result)
        st.plotly_chart(analysis_fig, use_container_width=True)

def show_settings_page():
    """Settings page"""
    st.markdown("## ⚙️ System Settings")
    
    st.markdown("### 🔧 Model Configuration")
    
    # Model path
    model_path = st.text_input("Model Path", value="gcn_model_weights.pth")
    
    if st.button("🔄 Reload Model"):
        try:
            st.session_state.detector = IntrusionDetector(model_path)
            st.success("✅ Model reloaded successfully!")
        except Exception as e:
            st.error(f"❌ Error reloading model: {str(e)}")
    
    st.markdown("### 📊 Detection Parameters")
    
    col1, col2 = st.columns(2)
    
    with col1:
        suspicious_port_min = st.number_input("Suspicious Port Min", value=1023, min_value=0, max_value=65535)
        suspicious_port_max = st.number_input("Suspicious Port Max", value=42000, min_value=0, max_value=65535)
    
    with col2:
        confidence_threshold = st.slider("Confidence Threshold", 0.0, 1.0, 0.5, 0.1)
        max_nodes_viz = st.number_input("Max Nodes for Visualization", value=50, min_value=10, max_value=200)
    
    st.markdown("### 💾 Export Options")
    
    if 'current_data' in st.session_state:
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📄 Export to CSV"):
                csv_data = st.session_state.data_processor.export_to_csv(st.session_state.current_data)
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name="network_flows.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📄 Export to JSON"):
                json_data = st.session_state.data_processor.export_to_json(st.session_state.current_data)
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name="network_flows.json",
                    mime="application/json"
                )

def show_about_page():
    """About page"""
    st.markdown("## ℹ️ About the System")
    
    st.markdown("""
    ### 🎯 System Overview
    
    This Network Intrusion Detection System uses advanced graph-based techniques to identify malicious network activity:
    
    - **Graph Convolutional Networks (GCN)**: Deep learning approach for graph classification
    - **Pattern Matching**: Rule-based detection of known attack patterns
    - **Incremental Analysis**: Efficient real-time processing of network flows
    
    ### 🔬 Technical Details
    
    **Detection Methods:**
    1. **Pattern 0**: Internal host → Multiple external hosts on suspicious ports
    2. **Pattern 1**: External host → Multiple internal hosts
    
    **Features:**
    - Source/Destination IP addresses
    - Port numbers and protocols
    - Network flow characteristics
    - Temporal patterns
    
    ### 📚 References
    
    - NetworkX for graph operations
    - PyTorch Geometric for GCN implementation
    - Streamlit for web interface
    - Plotly for interactive visualizations
    
    ### 👨‍💻 Development
    
    Built for advanced network security analysis and research purposes.
    """)
    
    st.markdown("---")
    st.markdown("**Version**: 1.0.0")
    st.markdown("**Last Updated**: 2024")

if __name__ == "__main__":
    main() 
