import win32pipe
import win32file
import pywintypes
import json
import time
from agents import malware_guard, network_guard

def process_winapi_data(winapi_data, alert_queue):
    # We pass the dictionary directly to the new analysis function in malware_guard
    risk_score, reasons = malware_guard.analyze_process(None,winapi_data)

    proc_name = winapi_data.get('name')
    proc_pid = winapi_data.get('pid')
    print(f"[DEBUG] risk score from malware guard for {proc_name}: {risk_score}")
    print(f"reasons: {reasons}")

    if risk_score >= 60:
        alert_msg = (f"NATIVE MALWARE ALERT: Suspicious process detected via WinAPI!\n"
                     f"Name: {proc_name}\n"
                     f"PID: {proc_pid}\n"
                     f"Risk Score: {risk_score}\n"
                     f"Reasons:\n - " + "\n - ".join(reasons))
        alert_queue.put(("THREAT", alert_msg))

    # Analyze network connections
    net_connections = winapi_data.get('net_connections', [])
    if net_connections:
        for conn in net_connections:
            risk_score, reasons = network_guard.calculate_connection_risk(
                proc_name,
                conn.get('remote_port'),
                network_guard.get_country(conn.get('remote_ip')),
                0, [] # No traffic data for now
            )
            print(f"[DEBUG] risk score from network guard {proc_name}:{conn.get('remote_ip')}: {risk_score}")
            print(f"reasons: {reasons}")
            
            if risk_score >= network_guard.BLOCK_TRESHOLD:

                if winapi_data.get('name') in network_guard.CRITICAL_PROCESSES:
                    continue

                msg = (f"NETWORK THREAT DETECTED!\n"
                        f"Process: {proc_name} (PID: {proc_pid})\n"
                        f"Destination: {conn.get('remote_ip')} ({network_guard.get_country(conn.get('remote_ip'))})\n"
                        f"Port: {conn.get('remote_port')}\n"
                        f"Reasons: {', '.join(reasons)}")
                    
                alert_queue.put(("THREAT", msg))


def start_monitoring(alert_queue, stop_event):
    """
    Main loop for the Named Pipe server. Listens for the C agent and handles data stream.
    """
    pipe_name = r'\\.\pipe\AegisPipe'
    # Outer loop ensures the server restarts if the C client disconnects
    while not stop_event.is_set():
        pipe_handle = None
        print("start monitoring")
        try:
            # Create the named pipe
            pipe_handle = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_INBOUND,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                1, 65536, 65536, 0, None
            )
            
            # Wait for the C agent to call CreateFileW
            win32pipe.ConnectNamedPipe(pipe_handle, None)
            alert_queue.put(("INFO", "SYSTEM: Native WinAPI Agent connected."))

            buffer = ""
            # Inner loop reads chunks of data until disconnection or stop signal
            while not stop_event.is_set():
                try:
                    # Read up to 64KB
                    result, data = win32file.ReadFile(pipe_handle, 65536)
                    #print("RAW:", repr(data))
                    buffer += data.decode('utf-8')

                    # Split buffer by newline character sent by the C agent
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line.strip():
                            try:
                                winapi_data = json.loads(line)
                                process_winapi_data(winapi_data, alert_queue)
                            except json.JSONDecodeError:
                                continue

                except pywintypes.error as e:
                    # Handle broken pipe / client closed
                    alert_queue.put(("ERROR", "SYSTEM: Native Agent disconnected."))
                    break 

        except Exception as e:
            time.sleep(1)
        finally:
            if pipe_handle:
                try:
                    win32pipe.DisconnectNamedPipe(pipe_handle)
                    win32file.CloseHandle(pipe_handle)
                except:
                    pass



if __name__ == "__main__":
    import queue
    import threading
    alert_queue = queue.Queue()
    stop_events = {}          
    stop_event = threading.Event()
    stop_events["name"] = stop_event
    start_monitoring(alert_queue,stop_event)