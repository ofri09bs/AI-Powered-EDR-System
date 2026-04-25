import customtkinter as ctk
import threading
import queue
import time
from datetime import datetime
from agents import malware_guard , phishing_guard, ransom_guard, network_guard, user_guard

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

root = None
alert_queue = queue.Queue()  
log_box = None
status_label = None
radar_label = None
agent_switches = {}        
running_threads = {}       
stop_events = {}          
last_threat_time = 0 

def log(message, level="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    base_msg = f"[{timestamp}] [{level}] {message}"
    
    if level in ["THREAT", "CRITICAL"]:
        final_msg = f"{base_msg}\n"
    else:
        final_msg = f"{base_msg}\n"
    
    if log_box:
        log_box.configure(state="normal") 
        log_box.insert("end", final_msg)
        log_box.see("end")              
        log_box.configure(state="disabled") 


def start_agent(name):
    global running_threads, stop_events
    
    stop_event = threading.Event()
    stop_events[name] = stop_event
    
    thread = None
    
    if name == "Malware Guard":
        if malware_guard:
            thread = threading.Thread(target=malware_guard.start_monitoring, 
                                      args=(alert_queue, stop_event))
        else:
            log("Error: malware_guard.py not found!", "ERROR")
            return

    elif name == "Phishing Guard":
        if phishing_guard:
            thread = threading.Thread(target=phishing_guard.start_monitoring, 
                                      args=(alert_queue, stop_event))
        else:
            log("Error: phishing_guard.py not found!", "ERROR")
            return

    elif name == "Ransom Guard":
        if ransom_guard:
            thread = threading.Thread(target=ransom_guard.start_monitoring, 
                                      args=(alert_queue, stop_event))
        else:
            log("Error: ransom_guard.py not found!", "ERROR")
            return
        
    elif name == "Network Guard":
        if network_guard:
            thread = threading.Thread(target=network_guard.start_monitoring, 
                                      args=(alert_queue, stop_event))
        else:
            log("Error: network_guard.py not found!", "ERROR")
            return
        
    elif name == "User Guard":
        if user_guard:
            thread = threading.Thread(target=user_guard.start_monitoring, 
                                      args=(alert_queue, stop_event))
        else:
            log("Error: user_guard.py not found!", "ERROR")
            return

    if thread:
        thread.daemon = True
        thread.start()
        running_threads[name] = thread
        log(f"Agent '{name}' STARTED.", "SYSTEM")

def stop_agent(name):
    if name in stop_events:
        log(f"Stopping {name}...", "SYSTEM")
        stop_events[name].set()
        del stop_events[name]
        if name in running_threads:
            del running_threads[name]

def toggle_agent_handler(name):
    is_active = agent_switches[name].get()
    
    if is_active:
        start_agent(name)
    else:
        stop_agent(name)


def check_alerts():
    global last_threat_time
    try:
        while not alert_queue.empty():
            alert_msg = alert_queue.get_nowait()
            
            if isinstance(alert_msg, tuple):
                level, msg = alert_msg
            else:
                level, msg = "THREAT", alert_msg

            if level == "THREAT":
                status_label.configure(text="THREAT DETECTED", text_color="#ff3333")
                radar_label.configure(text="⚠️ ANOMALY FOUND")
                last_threat_time = time.time()
                log(msg, "THREAT")

            elif level == "INFO":
                log(msg, "INFO")

            elif level == "ERROR":
                log(msg, "ERROR")

        if last_threat_time>0 and (time.time() - last_threat_time) > 4:
           if status_label.cget("text") != "SYSTEM SECURE":
                status_label.configure(text="SYSTEM SECURE", text_color="#00ff00")
                radar_label.configure(text="Monitoring endpoints...", text_color="gray")
                last_threat_time = 0

    except Exception as e:
        print(f"Error in check_alerts: {e}")
        pass
    finally:
        if root:
            root.after(500, check_alerts)



def panic_mode():
    log("!!! PANIC MODE INITIATED !!!", "CRITICAL")
    
    for name in list(stop_events.keys()):
        stop_agent(name)
        if name in agent_switches:
            agent_switches[name].deselect()

    status_label.configure(text="LOCKDOWN", text_color="red")
    radar_label.configure(text="NETWORK SEVERED | USB BLOCKED")
    

def init_gui():
    global root, log_box, status_label, radar_label
    
    root = ctk.CTk()
    root.title("PROJECT AEGIS - EDR COMMAND CENTER")
    root.geometry("1000x650")

    sidebar = ctk.CTkFrame(root, width=220, corner_radius=0)
    sidebar.pack(side="left", fill="y")

    ctk.CTkLabel(sidebar, text="🛡️ AEGIS", font=ctk.CTkFont(size=30, weight="bold")).pack(pady=30)
    ctk.CTkLabel(sidebar, text="Active Agents:", font=ctk.CTkFont(size=14)).pack(pady=(0, 10))

    agents_list = [
        "Malware Guard",
        "User Guard",
        "Ransom Guard",
        "Phishing Guard",
        "Network Guard"
    ]

    for agent in agents_list:
        switch_var = ctk.BooleanVar(value=False)
        agent_switches[agent] = switch_var
        switch = ctk.CTkSwitch(sidebar, text=agent, variable=switch_var, 
                               command=lambda n=agent: toggle_agent_handler(n))
        switch.pack(pady=10, padx=20, anchor="w")

    ctk.CTkButton(sidebar, text="LOCKDOWN SYSTEM", fg_color="#cc0000", hover_color="#990000", 
                  command=panic_mode).pack(side="bottom", pady=30, padx=20)

    # --- Main Area ---
    main_frame = ctk.CTkFrame(root, fg_color="transparent")
    main_frame.pack(side="right", fill="both", expand=True, padx=20, pady=20)

    # Status Header
    status_frame = ctk.CTkFrame(main_frame, height=150, corner_radius=10)
    status_frame.pack(fill="x", pady=(0, 20))
    
    status_label = ctk.CTkLabel(status_frame, text="SYSTEM SECURE", font=ctk.CTkFont(size=42, weight="bold"), text_color="#00ff00")
    status_label.place(relx=0.5, rely=0.4, anchor="center")
    
    radar_label = ctk.CTkLabel(status_frame, text="Monitoring endpoints...", font=ctk.CTkFont(size=18))
    radar_label.place(relx=0.5, rely=0.7, anchor="center")

    # Logs Console
    ctk.CTkLabel(main_frame, text="Security Event Log", anchor="w").pack(fill="x")
    log_box = ctk.CTkTextbox(main_frame, font=("Consolas", 14))
    log_box.pack(fill="both", expand=True)
    log_box.configure(state="disabled")

    log("Core initialized.")
    log("Standing by for agent activation.")
    
    check_alerts()
    root.mainloop()

if __name__ == "__main__":
    init_gui()