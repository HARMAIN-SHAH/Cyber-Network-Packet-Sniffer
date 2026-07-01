import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
from datetime import datetime


LOG_FILE = "packet_logs.txt"

sniffing = False


# Save packet logs
def save_log(data):
    with open(LOG_FILE, "a") as file:
        file.write(data + "\n")


# Analyze packets
def packet_analysis(packet):

    if sniffing and packet.haslayer(IP):

        time = datetime.now().strftime("%H:%M:%S")

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst


        if packet.haslayer(TCP):
            protocol = "TCP"

        elif packet.haslayer(UDP):
            protocol = "UDP"

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        else:
            protocol = "OTHER"


        size = len(packet)


        values = (
            time,
            src_ip,
            dst_ip,
            protocol,
            size
        )


        table.insert("", "end", values=values)


        log = f"""
Time: {time}
Source IP: {src_ip}
Destination IP: {dst_ip}
Protocol: {protocol}
Packet Size: {size} bytes
--------------------------
"""

        save_log(log)



# Start sniffing
def start_sniffer():

    global sniffing

    if not sniffing:

        sniffing = True

        status_label.config(
            text="STATUS : RUNNING",
            foreground="#00ff00"
        )

        thread = threading.Thread(
            target=capture_packets,
            daemon=True
        )

        thread.start()



def capture_packets():

    sniff(
        prn=packet_analysis,
        store=False
    )



# Stop sniffing
def stop_sniffer():

    global sniffing

    sniffing = False

    status_label.config(
        text="STATUS : STOPPED",
        foreground="red"
    )



# Clear table
def clear_table():

    for item in table.get_children():
        table.delete(item)



# GUI WINDOW

root = tk.Tk()

root.title("Cyber Network Sniffer")
root.geometry("900x500")
root.configure(bg="#050505")


# Heading

title = tk.Label(
    root,
    text="⚡ CYBER NETWORK PACKET SNIFFER ⚡",
    font=("Arial",18,"bold"),
    bg="#050505",
    fg="#00ff99"
)

title.pack(pady=15)



# Status

status_label = tk.Label(
    root,
    text="STATUS : STOPPED",
    font=("Arial",12,"bold"),
    bg="#050505",
    fg="red"
)

status_label.pack()



# Table Frame

frame = tk.Frame(root,bg="#050505")
frame.pack(pady=20)


columns = (
    "Time",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Size"
)


table = ttk.Treeview(
    frame,
    columns=columns,
    show="headings",
    height=12
)


for col in columns:

    table.heading(
        col,
        text=col
    )

    table.column(
        col,
        width=150
    )


table.pack()



# Buttons

button_frame = tk.Frame(
    root,
    bg="#050505"
)

button_frame.pack(pady=10)



start_btn = tk.Button(
    button_frame,
    text="START SNIFFING",
    command=start_sniffer,
    width=18,
    bg="#003300",
    fg="white",
    font=("Arial",10,"bold")
)


start_btn.grid(
    row=0,
    column=0,
    padx=10
)



stop_btn = tk.Button(
    button_frame,
    text="STOP",
    command=stop_sniffer,
    width=18,
    bg="#660000",
    fg="white",
    font=("Arial",10,"bold")
)


stop_btn.grid(
    row=0,
    column=1,
    padx=10
)



clear_btn = tk.Button(
    button_frame,
    text="CLEAR",
    command=clear_table,
    width=18,
    bg="#222222",
    fg="white",
    font=("Arial",10,"bold")
)


clear_btn.grid(
    row=0,
    column=2,
    padx=10
)



footer = tk.Label(
    root,
    text="Cyber Security Internship Project | Arch Technologies",
    bg="#050505",
    fg="gray",
    font=("Arial",10)
)

footer.pack(side="bottom", pady=10)



root.mainloop()