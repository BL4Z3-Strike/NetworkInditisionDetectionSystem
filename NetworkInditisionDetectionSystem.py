import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading
from collections import defaultdict
import time

# Known patterns for intrusion detection
KNOWN_PATTERNS = [
    {'src_port': 80, 'description': 'HTTP traffic on port 80'},
    {'src_port': 22, 'description': 'SSH traffic on port 22'},
]

# DDoS protection settings
RATE_LIMIT_WINDOW = 60  # Time window for rate limiting in seconds
MAX_REQUESTS = 100  # Maximum number of requests in the rate limit window

# Track requests from each IP address
request_counts = defaultdict(lambda: {'count': 0, 'last_request': time.time()})

# Function to analyze packets for known patterns and DDoS protection
def analyze_packet(packet, output_widget):
    try:
        src_ip = packet[IP].src if IP in packet else None
        src_port = None

        # Check for IP and TCP/UDP layers
        if TCP in packet:
            src_port = packet[TCP].sport
        elif UDP in packet:
            src_port = packet[UDP].sport

        # Rate Limiting for DDoS Protection
        if src_ip:
            now = time.time()
            request_info = request_counts[src_ip]
            if now - request_info['last_request'] > RATE_LIMIT_WINDOW:
                request_info['count'] = 0
                request_info['last_request'] = now
            
            request_info['count'] += 1
            if request_info['count'] > MAX_REQUESTS:
                alert_message = f"Rate limit exceeded from IP: {src_ip}\n"
                output_widget.insert(tk.END, alert_message)
                output_widget.yview(tk.END)
                return  # Skip further processing for this IP
        
        # Check for known patterns
        if src_port is not None:
            for pattern in KNOWN_PATTERNS:
                if src_port == pattern['src_port']:
                    alert_message = f"Suspicious activity detected: {pattern['description']} (Port: {src_port}, IP: {src_ip})\n"
                    output_widget.insert(tk.END, alert_message)
                    output_widget.yview(tk.END)
                    break
    except Exception as e:
        output_widget.insert(tk.END, f"Failed to analyze packet: {e}\n")
        output_widget.yview(tk.END)

# Function to capture network traffic and detect intrusions
def start_detection(output_widget):
    def run_detector():
        try:
            sniff(prn=lambda pkt: analyze_packet(pkt, output_widget), store=0)
        except Exception as e:
            output_widget.insert(tk.END, f"Failed to start detection: {e}\n")
            output_widget.yview(tk.END)

    # Start detection in a separate thread
    thread = threading.Thread(target=run_detector, daemon=True)
    thread.start()

# GUI Functions
def start_monitoring():
    start_detection(packet_output)

# Initialize Tkinter GUI
def create_gui():
    global packet_output

    root = tk.Tk()
    root.title("Network Intrusion Detection and DDoS Protection System")

    # Create and place widgets
    tk.Button(root, text="Start Monitoring", command=start_monitoring).grid(row=0, column=0, padx=10, pady=10)

    packet_output = scrolledtext.ScrolledText(root, height=20, width=80)
    packet_output.grid(row=1, column=0, padx=10, pady=10)

    root.mainloop()

if __name__ == '__main__':
    create_gui()
