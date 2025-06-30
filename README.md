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
   git clone https://github.com/Sakshi1027/graph-based-intrusion-detection.git
   cd graph-based-intrusion-detection
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

- **Sakshi A S**
- [Your GitHub Profile](https://github.com/Sakshi1027)

---

## 📄 License

This project is for educational and research purposes.



