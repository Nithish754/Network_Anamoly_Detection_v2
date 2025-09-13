import streamlit as st
import pandas as pd
import numpy as np
import tensorflow as tf
import time
import pickle
import threading
import random
from collections import deque
from queue import Queue
from sklearn.preprocessing import StandardScaler
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
from scapy.layers.inet import ICMP

# ==============================================================================
# Step 1: Initialize Global Variables / Session State
# ==============================================================================
time_steps = 10
features = ["DATA_00", "DATA_01", "DATA_02", "DATA_03"]

# Function to reset simulation state
def reset_simulation_state():
    """Reset all simulation-related session state variables"""
    st.session_state.stop_event = threading.Event()
    st.session_state.packets_data = []
    st.session_state.packet_buffer = deque(maxlen=time_steps)
    st.session_state.capture_thread = None
    st.session_state.data_queue = Queue()
    st.session_state.total_packets = 0
    st.session_state.total_attacks = 0
    st.session_state.total_benign = 0
    st.session_state.malicious_ips = set()
    st.session_state.simulation_active = False

# Session State Initialization
if "stop_event" not in st.session_state:
    reset_simulation_state()
    
# Set a threshold for auto-stopping the simulation
PACKET_THRESHOLD = 50 

# ==============================================================================
# Step 2: Load Model, Scaler, Encoder
# ==============================================================================
use_model = True
try:
    interpreter = tf.lite.Interpreter(model_path="lstm_model.tflite")
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_tensor_details()

    try:
        with open('scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
    except Exception as e:
        st.warning(f"⚠️ Could not load scaler, creating a new one. Error: {e}")
        training_data = pd.DataFrame(np.random.rand(100, 4), columns=features)
        scaler = StandardScaler()
        scaler.fit(training_data)
        with open('scaler.pkl', 'wb') as f:
            pickle.dump(scaler, f)

    with open('encoder.pkl', 'rb') as f:
        encoder = pickle.load(f)

except Exception as e:
    st.warning(f"⚠️ Could not load model/scaler/encoder. Using simulation mode. Error: {e}")
    use_model = False
    interpreter, input_details, output_details, scaler, encoder = None, None, None, None, None

# Define a more comprehensive list of attack types with weights for more variety
attack_types = ["Benign","DoS","DDoS","Spoofing","MITM","Brute Force","SQL Injection","XSS",
                "Phishing","Ransomware","Botnet","Worm","Trojan","Port Scanning","ARP Spoofing","DNS Spoofing"]

# ==============================================================================
# Step 3: Data Source Logic (Simulation & Real-Time)
# ==============================================================================
# A) Real-time packet capture with Scapy
def process_scapy_packet(packet):
    """
    Processes a Scapy packet and extracts features for the model.
    """
    features_dict = {
        "DATA_00": 0.0,
        "DATA_01": 0,
        "DATA_02": 0,
        "DATA_03": 0
    }
    src_ip, dst_ip = "Unknown", "Unknown"

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        features_dict["DATA_02"] = ip_layer.ttl 

        if TCP in packet:
            tcp_layer = packet[TCP]
            features_dict["DATA_01"] = sum([
                1 for f in ['S', 'A', 'F', 'R', 'P', 'U', 'E', 'C'] if f in str(tcp_layer.flags)
            ])
            features_dict["DATA_03"] = len(tcp_layer.payload)
            
        elif UDP in packet:
            udp_layer = packet[UDP]
            features_dict["DATA_01"] = 1
            features_dict["DATA_03"] = len(udp_layer.payload)

        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            features_dict["DATA_01"] = 2
            features_dict["DATA_03"] = len(icmp_layer.payload)
    
    if src_ip != "Unknown":
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "features": list(features_dict.values())
        }
    return None

def capture_real_packets(data_queue, stop_event, iface):
    """
    Sniffs packets from the specified network interface and puts them in a queue.
    """
    try:
        sniff(
            iface=iface, 
            prn=lambda p: data_queue.put(process_scapy_packet(p)) if process_scapy_packet(p) else None,
            stop_filter=lambda p: stop_event.is_set(),
            store=0,
            timeout=10 
        )
    except Exception as e:
        print(f"❌ Scapy Error in thread: {e}")
        
# B) Fake Packet Generator (for simulation mode)
def generate_fake_packet():
    src_networks = ["192.168.1", "10.0.0", "172.16.0", "203.0.113", "198.51.100"]
    dst_networks = ["10.0.0", "192.168.1", "172.16.1", "203.0.114"]
    
    src_ip = f"{random.choice(src_networks)}.{random.randint(2,254)}"
    dst_ip = f"{random.choice(dst_networks)}.{random.randint(2,254)}"
    
    packet_type = random.choice(["normal", "suspicious", "malicious"])
    
    if packet_type == "normal":
        features_dict = {
            "DATA_00": random.uniform(0.1, 0.8),
            "DATA_01": random.randint(1, 5),
            "DATA_02": random.randint(0, 2),
            "DATA_03": random.randint(64, 1500),
        }
    elif packet_type == "suspicious":
        features_dict = {
            "DATA_00": random.uniform(0.8, 1.5),
            "DATA_01": random.randint(5, 8),
            "DATA_02": random.randint(2, 4),
            "DATA_03": random.randint(20, 64),
        }
    else:  # malicious
        features_dict = {
            "DATA_00": random.uniform(1.5, 3.0),
            "DATA_01": random.randint(8, 10),
            "DATA_02": random.randint(4, 5),
            "DATA_03": random.randint(1, 20),
        }
    
    return src_ip, dst_ip, features_dict, packet_type

def process_and_queue_packet(data_queue, stop_event):
    while not stop_event.is_set():
        src_ip, dst_ip, features_dict, packet_type = generate_fake_packet()
        
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "features": list(features_dict.values()),
            "packet_type": packet_type
        }
        data_queue.put(log_entry)
        time.sleep(random.uniform(0.3, 0.7))

# ==============================================================================
# Step 4: Enhanced Prediction Logic
# ==============================================================================
def make_prediction(packet_buffer, log_entry, detection_mode):
    predicted_class_name = "Benign"
    confidence = 0.0
    
    if detection_mode == "Benign Mode":
        predicted_class_name = "Benign"
        confidence = 0.99
        return predicted_class_name, confidence

    # Anomaly Detection Logic
    is_known_malicious = log_entry['source_ip'] in st.session_state.malicious_ips
    
    if use_model and len(packet_buffer) == time_steps:
        df = pd.DataFrame(list(packet_buffer), columns=features)
        scaled_features = scaler.transform(df)
        input_data = np.array(scaled_features).astype(np.float32).reshape(1, time_steps, -1)
        interpreter.set_tensor(input_details[0]['index'], input_data)
        interpreter.invoke()
        output_data = interpreter.get_tensor(output_details[0]['index'])
        predicted_class_index = np.argmax(output_data)
        predicted_class_name = encoder.inverse_transform([predicted_class_index])[0]
        confidence = np.max(output_data)
    else:
        packet_type = log_entry.get('packet_type', 'normal')
        
        if is_known_malicious:
            predicted_class_name = random.choices([t for t in attack_types if t != "Benign"], 
                                                weights=[2, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1])[0]
            confidence = round(random.uniform(0.75, 0.95), 2)
        elif packet_type == "malicious":
            predicted_class_name = random.choices(attack_types, 
                                                weights=[0.1] + [0.9/15]*15)[0]
            confidence = round(random.uniform(0.65, 0.90), 2)
        elif packet_type == "suspicious":
            predicted_class_name = random.choices(attack_types, 
                                                weights=[0.4] + [0.6/15]*15)[0]
            confidence = round(random.uniform(0.55, 0.80), 2)
        else:
            predicted_class_name = random.choices(attack_types, 
                                                weights=[0.7] + [0.3/15]*15)[0]
            confidence = round(random.uniform(0.50, 0.75), 2)
    
    return predicted_class_name, confidence

# ==============================================================================
# Step 5: Streamlit UI Layout & Main Thread Logic
# ==============================================================================
st.set_page_config(page_title="🛡️ Network Anomaly Dashboard", layout="wide", page_icon="🛡️")
st.markdown("<h1 style='text-align: center; color: #4CAF50;'>🛡️ Network Anomaly Detection Dashboard</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center; color: #66BB6A;'>Powered by LSTM & Flexible Data Source</h3>", unsafe_allow_html=True)

# --- Sidebar for Data Source Selection (The "Plug and Play" part) ---
st.sidebar.header("🔌 Data Source Settings")
data_source = st.sidebar.radio(
    "Select your data source:",
    ("Simulation Mode", "Real-Time Capture")
)

interface_name = None
if data_source == "Real-Time Capture":
    st.sidebar.info("⚠️ Scapy requires root/admin privileges. Run with `sudo ...`")

    st.sidebar.subheader("Select Network Interface")
    available_interfaces = get_if_list()
    iface_options = [iface for iface in available_interfaces if iface != 'lo']
    
    # Add a custom option for manual entry
    iface_options.append("Manually Enter Interface Name")
    
    selected_iface = st.sidebar.selectbox(
        "Choose an available interface:",
        iface_options
    )
    
    if selected_iface == "Manually Enter Interface Name":
        interface_name = st.sidebar.text_input(
            "Enter Network Interface Name:",
            help="e.g., 'eth0', 'wlan0', 'enp3s0'. Use `ip addr` or `ifconfig` to find it."
        )
    else:
        interface_name = selected_iface

    st.sidebar.subheader("Detection Mode")
    detection_mode = st.sidebar.radio(
        "Choose analysis mode:",
        ("Detection Mode", "Benign Mode")
    )
    
    if not interface_name and not selected_iface == "Manually Enter Interface Name":
        st.sidebar.warning("Please select or enter a valid network interface name.")


# Enhanced Start / Stop / Reset Controls
col1, col2, col3 = st.columns([1,1,1])
with col1:
    if st.button("▶️ Start", key="start_button"):
        if not st.session_state.get('simulation_active', False):
            if data_source == "Real-Time Capture" and not interface_name:
                st.error("Please select or enter a network interface name.")
            else:
                st.session_state.stop_event.clear()
                st.session_state.simulation_active = True
                if data_source == "Simulation Mode":
                    st.session_state.capture_thread = threading.Thread(
                        target=process_and_queue_packet,
                        args=(st.session_state.data_queue, st.session_state.stop_event),
                        daemon=True
                    )
                    st.success("🚀 Simulation started...")
                else: # Real-Time Capture
                    st.session_state.capture_thread = threading.Thread(
                        target=capture_real_packets,
                        args=(st.session_state.data_queue, st.session_state.stop_event, interface_name),
                        daemon=True
                    )
                    st.success(f"🚀 Real-Time Packet Capture started on '{interface_name}'...")
                
                st.session_state.capture_thread.start()

with col2:
    if st.button("⏹️ Stop", key="stop_button"):
        if st.session_state.get('simulation_active', False):
            st.session_state.stop_event.set()
            st.session_state.simulation_active = False
            if st.session_state.capture_thread and st.session_state.capture_thread.is_alive():
                st.session_state.capture_thread.join(timeout=2)
            st.warning("⏸️ Operation stopped.")

with col3:
    if st.button("🔄 Reset & Restart", key="reset_button"):
        if st.session_state.get('simulation_active', False):
            st.session_state.stop_event.set()
            if st.session_state.capture_thread and st.session_state.capture_thread.is_alive():
                st.session_state.capture_thread.join(timeout=2)
        reset_simulation_state()
        st.info("🔄 Simulation reset. Click Start to begin a new session.")

# Display simulation status
if st.session_state.get('simulation_active', False):
    st.markdown("<p style='text-align: center; color: #4CAF50;'>🟢 Application is RUNNING</p>", unsafe_allow_html=True)
else:
    st.markdown("<p style='text-align: center; color: #F44336;'>🔴 Application is STOPPED</p>", unsafe_allow_html=True)

# Enhanced Dashboard Summary
st.markdown("---")
st.header("📊 Dashboard Summary")
col_summary1, col_summary2, col_summary3, col_summary4 = st.columns(4)
with col_summary1:
    st.metric(label="Total Packets", value=st.session_state.total_packets)
with col_summary2:
    st.metric(label="Predicted Attacks", value=st.session_state.total_attacks)
with col_summary3:
    st.metric(label="Benign Packets", value=st.session_state.total_benign)
with col_summary4:
    attack_percentage = (st.session_state.total_attacks / max(st.session_state.total_packets, 1)) * 100
    st.metric(label="Attack Rate %", value=f"{attack_percentage:.1f}%")

# Progress bar showing packet collection progress
if st.session_state.total_packets > 0:
    progress = min(st.session_state.total_packets / PACKET_THRESHOLD, 1.0)
    st.progress(progress)
    st.caption(f"Packets collected: {st.session_state.total_packets}/{PACKET_THRESHOLD}")

# Process packets from queue with enhanced logic
if st.session_state.get('simulation_active', False):
    packets_processed_this_cycle = 0
    try:
        while not st.session_state.data_queue.empty() and packets_processed_this_cycle < 5:
            log_entry = st.session_state.data_queue.get_nowait()
            packets_processed_this_cycle += 1
            
            st.session_state.packet_buffer.append(log_entry['features'])

            predicted_class_name, confidence = make_prediction(
                st.session_state.packet_buffer, 
                log_entry,
                detection_mode if data_source == "Real-Time Capture" else None # Pass detection mode only for real-time
            )
            
            is_known_malicious = log_entry['source_ip'] in st.session_state.malicious_ips

            final_log = {
                "timestamp": log_entry['timestamp'],
                "source_ip": log_entry['source_ip'],
                "destination_ip": log_entry['destination_ip'],
                "prediction": predicted_class_name,
                "confidence": confidence,
                "known_threat": is_known_malicious
            }
            st.session_state.packets_data.append(final_log)
            
            if final_log['prediction'] != "Benign":
                st.session_state.total_attacks += 1
                st.session_state.malicious_ips.add(final_log['source_ip'])
            else:
                st.session_state.total_benign += 1
            st.session_state.total_packets += 1

    except Exception as e:
        st.error(f"Error processing packets: {e}")

    if st.session_state.total_packets >= PACKET_THRESHOLD:
        st.session_state.stop_event.set()
        st.session_state.simulation_active = False
        st.success(f"✅ Capture completed! Collected {PACKET_THRESHOLD} packets. Click Reset & Restart for a new session.")

    if st.session_state.get('simulation_active', False):
        time.sleep(0.5)
        st.rerun()

# ==============================================================================
# Step 6: Enhanced Tabs for Organized UI
# ==============================================================================
if st.session_state.packets_data:
    tabs = st.tabs(["📊 Live Predictions","🚨 Malicious Summary","📚 Attack Details","🌡️ Severity & IP Heatmap"])

    # ================= Live Predictions Tab =================
    with tabs[0]:
        st.header("📡 Live Network Predictions")
        df_live = pd.DataFrame(st.session_state.packets_data).tail(20)
        df_live['Threat Status'] = df_live['known_threat'].apply(
            lambda x: "🚫 Blocked IP" if x else "✅ New packet"
        )
        
        def highlight_attacks(val):
            if val != "Benign":
                return 'background-color: #A32D2D; color: white;'
            return ''
        
        styled_df = df_live[['timestamp', 'source_ip', 'destination_ip', 'prediction', 'confidence', 'Threat Status']].style.applymap(
            highlight_attacks, subset=['prediction'])
        
        st.dataframe(styled_df, use_container_width=True)

    # ================= Malicious Summary Tab =================
    with tabs[1]:
        st.header("🚨 Malicious Activity Summary")
        df = pd.DataFrame(st.session_state.packets_data)
        malicious_df = df[df['prediction'] != "Benign"]
        
        if not malicious_df.empty:
            st.subheader("🎯 Attack Type Distribution")
            attack_counts = malicious_df['prediction'].value_counts()
            
            fig_bar = px.bar(x=attack_counts.index, y=attack_counts.values,
                            title="Attack Type Frequency",
                            labels={'x': 'Attack Type', 'y': 'Count'},
                            color_discrete_sequence=px.colors.qualitative.Plotly)
            st.plotly_chart(fig_bar, use_container_width=True)

            st.subheader("📊 Attack Type Percentage")
            attack_percentage = attack_counts.reset_index()
            attack_percentage.columns = ["Attack","Count"]
            fig1 = px.pie(attack_percentage, values='Count', names='Attack', 
                         title="Attack Distribution",
                         hover_data=['Count'], 
                         labels={'Count':'Packets Detected'})
            fig1.update_traces(textinfo='percent+label')
            st.plotly_chart(fig1, use_container_width=True)

            st.subheader("🕒 Recent Malicious Activity")
            recent_attacks = malicious_df.tail(10)[['timestamp', 'source_ip', 'prediction', 'confidence']]
            st.dataframe(recent_attacks, use_container_width=True)
        else:
            st.info("No malicious activity detected yet.")

    # ================= Attack Details Tab =================
    with tabs[2]:
        st.header("📚 Attack Details and Prevention")
        attack_info = {
            "Benign": {"description":"Normal, legitimate network traffic","cause":"Standard user activities and system operations","prevention":"None required - this is normal traffic"},
            "DoS": {"description":"Denial of Service - floods a network with malicious packets, overwhelming the system.","cause":"Excessive service requests from a single source to consume resources.","prevention":"Rate limiting, firewalls, load balancers, and IDS monitoring."},
            "DDoS": {"description":"Distributed Denial of Service - coordinated attack from multiple sources.","cause":"Botnet-controlled devices attacking simultaneously.","prevention":"Content Delivery Networks (CDNs), traffic filtering, and DDoS protection services."},
            "Spoofing": {"description":"An attacker impersonates a trusted entity by forging network identifiers.","cause":"Modified packet headers, fake source IPs, or MAC address manipulation.","prevention":"Ingress/egress filtering, strong authentication protocols, and network access control."},
            "MITM": {"description":"Man-in-the-Middle - attacker secretly intercepts and relays communication.","cause":"Weak encryption, compromised network infrastructure, or ARP poisoning.","prevention":"End-to-end encryption (TLS/SSL), VPNs, certificate pinning, and secure key exchange."},
            "Brute Force": {"description":"Systematic attempts to guess passwords, keys, or access credentials.","cause":"Weak authentication mechanisms and easily guessable passwords.","prevention":"Multi-Factor Authentication (MFA), account lockout policies, CAPTCHAs, and strong password requirements."},
            "SQL Injection": {"description":"Malicious SQL code injection to manipulate database queries.","cause":"Improper input validation and lack of parameterized queries in web applications.","prevention":"Prepared statements, input sanitization, least privilege database accounts, and code reviews."},
            "XSS": {"description":"Cross-Site Scripting - injecting malicious scripts into web pages.","cause":"Improper input validation allowing script execution in browsers.","prevention":"Input validation, output encoding, Content Security Policy (CSP), and secure coding practices."},
            "Phishing": {"description":"Social engineering to steal sensitive information through deception.","cause":"Fraudulent emails, websites, or messages mimicking legitimate entities.","prevention":"User awareness training, email filtering, multi-factor authentication, and security awareness."},
            "Ransomware": {"description":"Malicious software that encrypts files and demands ransom payment.","cause":"Malware infection through email attachments, downloads, or system vulnerabilities.","prevention":"Regular backups, endpoint protection, patch management, and user education."},
            "Botnet": {"description":"Network of compromised devices under remote attacker control.","cause":"Malware infection allowing unauthorized remote access and control.","prevention":"Antivirus software, firewalls, network monitoring, and regular system updates."},
            "Worm": {"description":"Self-replicating malware that spreads across networks automatically.","cause":"Exploitation of unpatched software vulnerabilities for autonomous spreading.","prevention":"Regular security updates, network segmentation, Intrusion Detection Systems, and endpoint protection."},
            "Trojan": {"description":"Malicious software disguised as legitimate applications.","cause":"Users unknowingly installing malware disguised as useful software.","prevention":"Antivirus software, application whitelisting, downloading from trusted sources only."},
            "Port Scanning": {"description":"Network reconnaissance to identify open ports and potential vulnerabilities.","cause":"Automated tools probing network services for security assessment or attack preparation.","prevention":"Firewall configuration, intrusion detection, port knocking, and network segmentation."},
            "ARP Spoofing": {"description":"Address Resolution Protocol manipulation to intercept network traffic.","cause":"Sending false ARP messages to associate attacker's MAC with victim's IP address.","prevention":"Static ARP entries, dynamic ARP inspection, network monitoring, and switch security features."},
            "DNS Spoofing": {"description":"Domain Name System manipulation to redirect traffic to malicious servers.","cause":"DNS cache poisoning or compromised DNS servers providing false resolution.","prevention":"DNSSEC implementation, secure DNS resolvers, DNS over HTTPS/TLS, and network monitoring."}
        }
        
        selected_attack = st.selectbox("🔍 Select Attack Type for Details", list(attack_info.keys()))
        info = attack_info.get(selected_attack)
        if info:
            st.markdown(f"**📝 Description:** {info['description']}")
            st.markdown(f"**🔍 Root Cause:** {info['cause']}")
            st.markdown(f"**🛡️ Prevention Methods:** {info['prevention']}")

    # ================= Severity & IP Heatmap Tab =================
    with tabs[3]:
        st.header("🌡️ Threat Severity & IP Analysis")
        df = pd.DataFrame(st.session_state.packets_data)
        
        severity_mapping = {
            "Benign": "Safe", "Port Scanning": "Low", "Spoofing": "Medium", "ARP Spoofing": "Medium",
            "Phishing": "Medium", "XSS": "Medium", "MITM": "High", "DoS": "High", "DDoS": "High", 
            "SQL Injection": "High", "Brute Force": "High", "Trojan": "High", "Worm": "High", 
            "Botnet": "Critical", "Ransomware": "Critical", "DNS Spoofing": "High"
        }
        
        df['Severity'] = df['prediction'].map(severity_mapping).fillna("Unknown")

        st.subheader("⚠️ Threat Severity Distribution")
        severity_counts = df['Severity'].value_counts()
        
        severity_colors = {'Safe': '#4CAF50', 'Low': '#FFC107', 'Medium': '#FF9800', 'High': '#F44336', 'Critical': '#B71C1C'}
        
        fig_severity = px.bar(x=severity_counts.index, y=severity_counts.values, 
                             title="Threat Levels Detected",
                             color=severity_counts.index,
                             color_discrete_map=severity_colors)
        st.plotly_chart(fig_severity, use_container_width=True)

        st.subheader("🎯 Most Active Threat Sources")
        malicious_traffic = df[df['Severity'] != "Safe"]
        if not malicious_traffic.empty:
            ip_activity = malicious_traffic.groupby('source_ip').agg({
                'prediction': 'count',
                'Severity': lambda x: x.mode().iloc[0] if not x.empty else 'Unknown'
            }).rename(columns={'prediction': 'Threat_Count', 'Severity': 'Primary_Threat_Level'})
            ip_activity = ip_activity.sort_values('Threat_Count', ascending=False).head(10)
            st.dataframe(ip_activity.reset_index(), use_container_width=True)

            st.subheader("🗺️ Attack Pattern Heatmap")
            try:
                heatmap_source_data = malicious_traffic.groupby(['source_ip', 'prediction']).size().reset_index(name='count')
                
                if len(heatmap_source_data) > 0:
                    heatmap_pivot = heatmap_source_data.pivot(index='source_ip', columns='prediction', values='count').fillna(0)
                    
                    if not heatmap_pivot.empty and heatmap_pivot.shape[0] > 1 and heatmap_pivot.shape[1] > 1:
                        fig_heatmap = px.imshow(
                            heatmap_pivot,
                            title="🔥 Source IP vs Attack Type Heat Map",
                            labels=dict(x="Attack Type", y="Source IP", color="Attack Frequency"),
                            aspect="auto",
                            color_continuous_scale="Viridis",
                            text_auto=True
                        )
                        
                        fig_heatmap.update_layout(
                            title_font_size=16,
                            title_x=0.5,
                            xaxis_title_font_size=14,
                            yaxis_title_font_size=14,
                            height=500
                        )
                        
                        fig_heatmap.update_traces(
                            texttemplate="%{z}",
                            textfont={"size": 12, "color": "white"}
                        )
                        
                        st.plotly_chart(fig_heatmap, use_container_width=True)
                    else:
                        st.info("🔄 Collecting more attack data to generate comprehensive heatmap...")
                        
                        st.subheader("📊 Current Attack Summary")
                        attack_summary = heatmap_source_data.groupby('prediction')['count'].sum().reset_index()
                        attack_summary.columns = ['Attack Type', 'Total Occurrences']
                        attack_summary = attack_summary.sort_values('Total Occurrences', ascending=False)
                        st.dataframe(attack_summary, use_container_width=True)
                else:
                    st.info("🕐 No attack pattern data available yet. Continue the simulation to see attack patterns.")
                    
            except Exception as e:
                st.error(f"Error generating heatmap: {e}")
                st.info("📊 Showing alternative attack distribution view:")
                
                attack_by_ip = malicious_traffic.groupby('source_ip')['prediction'].value_counts().reset_index()
                attack_by_ip.columns = ['Source IP', 'Attack Type', 'Count']
                st.dataframe(attack_by_ip.head(20), use_container_width=True)
        else:
            st.info("No threat sources identified yet.")
else:
    st.info("👆 Start the selected mode to begin collecting and analyzing network traffic data.")

# Footer
st.markdown("---")
st.markdown("🛡️ **Network Anomaly Detection Dashboard** - Real-time threat monitoring and analysis")