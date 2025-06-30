# 🛡️ Network Intrusion Detection System (NIDS)

A modern, interactive web application for detecting network intrusions using Graph Convolutional Networks (GCN) and pattern matching, built with Streamlit.

---

## 📖 Project Overview

This project is a **Network Intrusion Detection System (NIDS)** that leverages advanced graph-based techniques and deep learning to identify malicious activity in network traffic. The system provides a user-friendly web interface for uploading, analyzing, and visualizing network flow data. It combines the power of Graph Convolutional Networks (GCN) for anomaly detection with rule-based pattern matching for known attack signatures.

---

## 🚀 Features

- **Graph-based Intrusion Detection** using GCN deep learning
- **Pattern Matching** for known attack signatures
- **Interactive Visualizations** (Plotly)
- **Real-time Data Analysis**
- **User-friendly Web UI** (Streamlit)
- **Support for CSV/JSON network flow data**
- **Export analysis results**

---

## 📦 Project Structure

```
lab_el_final/
│
├── app.py                  # Main Streamlit app
├── gcn_model.py            # GCN model implementation
├── data_processor.py       # Data processing utilities
├── visualizer.py           # Visualization utilities
├── gcn_model_weights.pth   # Pre-trained model weights
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
└── (Optional: sample data files)
```

---

## 🛠️ How to Clone and Install

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/lab_el_final.git
   cd lab_el_final
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional) Add your own data files**  
   Place any CSV/JSON network flow data in the project directory for analysis.

---

## 🏃‍♂️ How to Run the App Locally

```bash
streamlit run app.py
```
- The app will open in your browser at `http://localhost:8501`.

---

## 🌐 Deploying on Render

1. **Push your code to GitHub.**
2. **Create a new Web Service on [Render](https://render.com/):**
   - **Build Command:**  
     `pip install -r requirements.txt`
   - **Start Command:**  
     `streamlit run app.py --server.port $PORT --server.address 0.0.0.0`
3. **Wait for deployment and access your public URL!**

---

## 📊 Usage Guide

- **Home:** Overview and quick stats
- **Upload & Analyze:** Upload CSV/JSON, run intrusion detection
- **Visualizations:** Explore data and detection results
- **Settings:** Configure model and export data
- **About:** System details and references

---

## 📝 Requirements

- Python 3.8+
- Streamlit
- pandas
- plotly
- torch
- networkx
- (see `requirements.txt` for full list)

---

## 📚 References

- [Streamlit](https://streamlit.io/)
- [PyTorch](https://pytorch.org/)
- [Plotly](https://plotly.com/python/)
- [NetworkX](https://networkx.org/)

---

## 👨‍💻 Author

- **Your Name**
- [Your GitHub Profile](https://github.com/yourusername)

---

## 📄 License

This project is for educational and research purposes.

## 🎯 Features

- **Graph-Based Analysis**: Uses NetworkX for network graph construction and analysis
- **GCN Neural Network**: Deep learning approach for graph classification
- **Pattern Matching**: Rule-based detection of known attack patterns
- **Real-time Processing**: Incremental analysis for efficient detection
- **Interactive UI**: Beautiful Streamlit web interface
- **Multiple Formats**: Support for CSV and JSON data formats
- **Visualizations**: Interactive charts and network graphs

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python run_app.py
   ```
   
   Or directly with Streamlit:
   ```bash
   streamlit run app.py
   ```

4. **Open your browser** and go to `http://localhost:8501`

## 📁 Project Structure

```
lab_el_final/
├── app.py                          # Main Streamlit application
├── run_app.py                      # Launcher script
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── gcn_model_weights.pth          # Pre-trained GCN model
├── models/
│   └── gcn_model.py               # GCN model and detector classes
├── utils/
│   ├── data_processor.py          # Data processing utilities
│   └── visualizer.py              # Visualization functions
├── *.csv                          # Sample data files
└── *.ipynb                        # Jupyter notebook with original analysis
```

## 🔧 Usage

### 1. Home Page
- Overview of the system
- Quick start guide
- System status

### 2. Upload & Analyze
- Upload CSV or JSON network flow data
- Use sample data for testing
- Run intrusion detection analysis
- View detailed results

### 3. Visualizations
- Data summary charts
- Network flow timeline
- Interactive network graphs
- Attack analysis dashboard

### 4. Settings
- Model configuration
- Detection parameters
- Export options

## 📊 Data Format

The system expects network flow data with the following columns:

| Column | Description | Example |
|--------|-------------|---------|
| Source IP | Source IP address | 192.168.10.1 |
| Destination IP | Destination IP address | 8.8.8.8 |
| Source Port | Source port number | 12345 |
| Destination Port | Destination port number | 80 |
| Protocol | Protocol number | 6 (TCP) |
| Label | Traffic label | BENIGN/ATTACK |

### Sample CSV Format:
```csv
Source IP,Destination IP,Source Port,Destination Port,Protocol,Label
192.168.10.1,8.8.8.8,12345,80,6,BENIGN
192.168.10.2,1.1.1.1,54321,443,6,ATTACK
```

## 🔬 Detection Methods

### Pattern 0: Internal to External Suspicious Connections
- Detects internal hosts making connections to multiple external hosts
- Focuses on suspicious port ranges (1024-42000)
- Identifies potential data exfiltration attempts

### Pattern 1: External to Internal Multiple Connections
- Detects external hosts making multiple connections to internal hosts
- Identifies potential scanning or attack attempts
- Monitors for unusual connection patterns

### GCN Neural Network
- Graph Convolutional Network for deep learning analysis
- Uses node features (in-degree, out-degree)
- Provides probability scores for attack detection

## 🎨 Visualizations

- **Network Graph**: Interactive visualization of network topology
- **Attack Analysis**: Dashboard with confidence scores and pattern detection
- **Data Summary**: Charts showing protocol distribution, port ranges, etc.
- **Timeline**: Network flow activity over time

## ⚙️ Configuration

### Model Settings
- Model path: `gcn_model_weights.pth`
- Suspicious port range: 1024-42000
- Confidence threshold: 0.5

### Detection Parameters
- Internal IP range: 192.168.10.x
- Pattern matching sensitivity
- Visualization node limits

## 🛠️ Development

### Adding New Patterns
1. Modify `detect_malicious_patterns()` in `models/gcn_model.py`
2. Add pattern logic to the detection function
3. Update pattern descriptions in the UI

### Customizing Visualizations
1. Edit `utils/visualizer.py`
2. Add new chart types
3. Modify color schemes and layouts

### Extending Data Processing
1. Update `utils/data_processor.py`
2. Add support for new file formats
3. Implement custom data validation

## 📈 Performance

- **Real-time Analysis**: Incremental graph updates
- **Scalable**: Handles large network datasets
- **Accurate**: Combines rule-based and ML approaches
- **Efficient**: Optimized graph operations

## 🔒 Security Features

- Input validation and sanitization
- Secure file handling
- Error handling and logging
- Session management

## 📚 Dependencies

### Core Libraries
- **PyTorch**: Deep learning framework
- **PyTorch Geometric**: Graph neural networks
- **NetworkX**: Graph operations
- **Pandas**: Data manipulation
- **NumPy**: Numerical computing

### Visualization
- **Streamlit**: Web interface
- **Plotly**: Interactive charts
- **Matplotlib**: Static plots
- **Seaborn**: Statistical visualizations

### Data Processing
- **Scikit-learn**: Machine learning utilities
- **JSON**: Data serialization

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is for educational and research purposes.

## 🆘 Troubleshooting

### Common Issues

1. **Import Errors**: Make sure all dependencies are installed
   ```bash
   pip install -r requirements.txt
   ```

2. **Model Loading Error**: Check if `gcn_model_weights.pth` exists
   - The model file should be in the root directory

3. **Port Already in Use**: Change the port in `run_app.py`
   ```python
   "--server.port", "8502"  # Change to different port
   ```

4. **Memory Issues**: Reduce visualization node limits in settings

### Getting Help

- Check the console output for error messages
- Verify your data format matches the expected schema
- Ensure all required files are present

## 🎓 Academic Use

This system demonstrates:
- Graph-based machine learning
- Network security analysis
- Real-time intrusion detection
- Interactive data visualization
- Modern web application development

Perfect for:
- Computer Science projects
- Network Security research
- Machine Learning studies
- Data Visualization courses 
