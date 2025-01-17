import streamlit as st
import pandas as pd
import numpy as np
import time
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px

# Set page config
st.set_page_config(
    page_title="Network Security Monitor",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS with dark theme and enhanced sidebar styling
st.markdown("""
    <style>
    /* Dark theme styles */
    .stApp {
        background-color: #1a1a1a;
        color: #ffffff;
    }
    
    .metric-card {
        background-color: #2d2d2d;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        color: #ffffff;
        border: 1px solid #3d3d3d;
    }
    
    .metric-card h3 {
        color: #0ea5e9;
        margin-bottom: 8px;
    }
    
    .threat-card {
        background-color: #2d2d2d;
        padding: 15px;
        border-radius: 10px;
        margin-bottom: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        border: 1px solid #3d3d3d;
    }
    
    .stAlert {
        background-color: #2d2d2d;
        color: white;
        border: 1px solid #3d3d3d;
    }
    
    /* Enhanced sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #2d2d2d;
        border-right: 1px solid #3d3d3d;
    }
    
    section[data-testid="stSidebar"] .stMarkdown {
        color: white;
    }
    
    section[data-testid="stSidebar"] .stSelectbox label,
    section[data-testid="stSidebar"] .stMultiSelect label,
    section[data-testid="stSidebar"] .stSlider label {
        color: white !important;
    }
    
    /* Style for all select boxes in sidebar */
    section[data-testid="stSidebar"] .stSelectbox > div > div,
    section[data-testid="stSidebar"] .stMultiSelect > div > div {
        background-color: #3d3d3d;
        color: white;
        border: 1px solid #4d4d4d;
    }
    
    /* Slider styling */
    section[data-testid="stSidebar"] .stSlider > div > div {
        background-color: #3d3d3d;
    }
    
    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
        background-color: #1a1a1a;
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: #2d2d2d;
        color: #ffffff;
        border-radius: 4px 4px 0 0;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #0ea5e9;
    }

    /* Button styling */
    .stButton > button {
        background-color: #3d3d3d;
        color: white;
        border: 1px solid #4d4d4d;
    }

    .stButton > button:hover {
        background-color: #4d4d4d;
        border: 1px solid #5d5d5d;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = True
if 'alert_count' not in st.session_state:
    st.session_state.alert_count = 3
if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now()
if 'threat_log' not in st.session_state:
    st.session_state.threat_log = []

# Sidebar configuration
with st.sidebar:
    st.title("🔧 Configuration")
    st.subheader("Monitoring Settings")
    alert_threshold = st.slider("Alert Threshold (Mb/s)", 0, 1000, 500)
    scan_interval = st.selectbox("Scan Interval", ["30 seconds", "1 minute", "5 minutes"])
    
    st.subheader("Filter Settings")
    protocols_to_monitor = st.multiselect(
        "Protocols to Monitor",
        ["HTTP/HTTPS", "TCP", "UDP", "ICMP", "DNS", "FTP"],
        default=["HTTP/HTTPS", "TCP", "UDP"]
    )
    
    st.subheader("Alert Settings")
    alert_types = st.multiselect(
        "Alert Types",
        ["Port Scan", "DDoS Attack", "Brute Force", "Malware Detection", "Data Exfiltration"],
        default=["Port Scan", "DDoS Attack", "Brute Force"]
    )

# Header
col1, col2, col3 = st.columns([3, 1, 1])
with col1:
    st.title("🛡 Network Security Monitor")
    st.markdown("Real-time network traffic analysis and threat detection")
with col2:
    monitoring_status = st.toggle("Monitoring Active", value=st.session_state.monitoring_active)
with col3:
    st.metric("Last Update", f"{(datetime.now() - st.session_state.last_update).seconds}s ago")

# Data generation functions
def generate_traffic_data():
    return {
        'incoming': np.random.randint(50, 150),
        'outgoing': np.random.randint(30, 110),
        'total': np.random.randint(100, 250),
        'blocked': np.random.randint(10, 50)
    }

def generate_protocol_data():
    protocols = protocols_to_monitor
    values = np.random.randint(100, 1500, size=len(protocols))
    colors = px.colors.qualitative.Set3[:len(protocols)]
    return pd.DataFrame({
        'Protocol': protocols,
        'Value': values,
        'Color': colors
    })

def generate_time_series():
    times = pd.date_range(end=datetime.now(), periods=20, freq='1min')
    return pd.DataFrame({
        'time': times,
        'traffic': np.random.randint(500, 1500, size=20),
        'packets': np.random.randint(100, 300, size=20),
        'anomaly_score': np.random.uniform(0, 1, size=20)
    })

def generate_threat_data():
    threat_types = [
        "Port Scan", "DDoS Attack", "Brute Force",
        "Malware Detection", "Suspicious Traffic",
        "Data Exfiltration", "Unknown Threat"
    ]
    return {
        'type': np.random.choice(threat_types),
        'source_ip': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
        'destination_ip': f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
        'severity': np.random.choice(['Critical', 'High', 'Medium', 'Low']),
        'timestamp': datetime.now() - timedelta(minutes=np.random.randint(0, 60))
    }

# Tabs for different views
tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "🎯 Threat Hunting", "📝 Logs"])

# Dashboard Tab
with tab1:
    # Enhanced Metrics
    metrics_cols = st.columns(4)
    traffic_data = generate_traffic_data()

    with metrics_cols[0]:
        st.markdown(f"""
            <div class="metric-card">
                <h3>Current Traffic</h3>
                <h2>{traffic_data['total']} Mb/s</h2>
                <small>↑ {traffic_data['incoming']} Mb/s | ↓ {traffic_data['outgoing']} Mb/s</small>
            </div>
        """, unsafe_allow_html=True)

    with metrics_cols[1]:
        st.markdown(f"""
            <div class="metric-card">
                <h3>Protected Hosts</h3>
                <h2>142</h2>
                <small>Active Firewalls: 12</small>
            </div>
        """, unsafe_allow_html=True)

    with metrics_cols[2]:
        st.markdown(f"""
            <div class="metric-card">
                <h3>Active Alerts</h3>
                <h2>{st.session_state.alert_count}</h2>
                <small>Blocked: {traffic_data['blocked']}</small>
            </div>
        """, unsafe_allow_html=True)

    with metrics_cols[3]:
        st.markdown(f"""
            <div class="metric-card">
                <h3>Security Score</h3>
                <h2>{np.random.randint(85, 98)}%</h2>
                <small>Last 24h: +2.3%</small>
            </div>
        """, unsafe_allow_html=True)

    # Enhanced Charts
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Network Traffic Trend")
        time_series = generate_time_series()
        
        # Create a more detailed traffic trend visualization
        fig = go.Figure()
        
        # Add traffic line
        fig.add_trace(go.Scatter(
            x=time_series['time'],
            y=time_series['traffic'],
            name='Traffic',
            line=dict(color='#0ea5e9', width=2),
            fill='tozeroy',
            fillcolor='rgba(14, 165, 233, 0.1)'
        ))
        
        # Add anomaly score as a secondary axis
        fig.add_trace(go.Scatter(
            x=time_series['time'],
            y=time_series['anomaly_score'],
            name='Anomaly Score',
            line=dict(color='#ef4444', width=1, dash='dot'),
            yaxis='y2'
        ))

        fig.update_layout(
            height=400,
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(45,45,45)',
            font_color='white',
            xaxis=dict(
                gridcolor='rgba(128,128,128,0.1)',
                zerolinecolor='rgba(128,128,128,0.1)',
                title='Time'
            ),
            yaxis=dict(
                gridcolor='rgba(128,128,128,0.1)',
                zerolinecolor='rgba(128,128,128,0.1)',
                title='Traffic (Mb/s)'
            ),
            yaxis2=dict(
                title='Anomaly Score',
                overlaying='y',
                side='right',
                range=[0, 1],
                gridcolor='rgba(128,128,128,0.1)',
                zerolinecolor='rgba(128,128,128,0.1)'
            ),
            showlegend=True,
            legend=dict(
                bgcolor='rgba(45,45,45,0.8)',
                bordercolor='rgba(128,128,128,0.1)',
                borderwidth=1
            )
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Protocol Distribution")
        protocol_data = generate_protocol_data()
        fig = px.pie(protocol_data, values='Value', names='Protocol', hole=0.4,
                    color_discrete_sequence=protocol_data['Color'])
        fig.update_layout(
            height=400,
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(45,45,45)',
            font_color='white'
        )
        st.plotly_chart(fig, use_container_width=True)

# Threat Hunting Tab
with tab2:
    st.subheader("Active Threat Detection")
    
    # Threat map placeholder
    st.markdown("""
        <div style='background-color: blue; padding: 20px; border-radius: 10px; margin-bottom: 20px;'>
            [Threat Map Visualization Would Go Here]
        </div>
    """, unsafe_allow_html=True)
    
    # Real-time threat scanning
    scan_col1, scan_col2 = st.columns(2)
    with scan_col1:
        if st.button("Start Deep Scan"):
            with st.spinner("Scanning network..."):
                time.sleep(2)
                st.success("Scan completed! No critical vulnerabilities found.")
    
    with scan_col2:
        st.download_button(
            label="Export Threat Report",
            data="Sample threat report data",
            file_name="threat_report.csv",
            mime="text/csv"
        )

# Logs Tab
with tab3:
    st.subheader("Security Event Logs")
    
    # Generate some mock logs
    if monitoring_status:
        new_threat = generate_threat_data()
        st.session_state.threat_log.append(new_threat)
    
    # Display logs with filtering
    log_filter = st.selectbox("Filter by Severity", 
                             ["All", "Critical", "High", "Medium", "Low"])
    
    filtered_logs = st.session_state.threat_log
    if log_filter != "All":
        filtered_logs = [log for log in filtered_logs if log['severity'] == log_filter]
    
    for log in filtered_logs[-10:]:  # Show last 10 logs
        severity_color = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵"
        }[log['severity']]
        
        st.markdown(f"""
            <div class="threat-card">
                <div style='display: flex; justify-content: space-between; align-items: center;'>
                    <div>
                        <strong>{severity_color} {log['type']}</strong>
                        <br/>
                        <small style='color: gray;'>
                            Source: {log['source_ip']} → Destination: {log['destination_ip']} | 
                            Severity: {log['severity']}
                        </small>
                    </div>
                    <small style='color: gray;'>{log['timestamp'].strftime('%H:%M:%S')}</small>
                </div>
            </div>
        """, unsafe_allow_html=True)

# Auto-refresh functionality
if monitoring_status:
    time.sleep(2)
    st.rerun()