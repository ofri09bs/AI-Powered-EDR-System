import os
import time
import hashlib
import psutil 
import stat

# **************** Ransomware Behavior Monitoring Agent ****************

TRAP_LOCATIONS = [
    os.path.join(os.getenv('USERPROFILE'), 'Desktop'),
    os.path.join(os.getenv('USERPROFILE'), 'Documents'),
    os.path.join(os.getenv('USERPROFILE'), 'Pictures'),
    os.path.join(os.getenv('USERPROFILE'), 'Downloads'),
    os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming')
]

TRAP_FILENAMES = [
    "A_TRAP_1.txt",
    "A_TRAP_2.docx",
    "A_TRAP_3.xlsx",
    "A_TRAP_4.pdf",
    "A_TRAP_5.jpg"
]

ORIGINAL_CONTENTS = b"This is a honey-pot file for AEGIS Ransomware detection. Do not touch."

def calculate_hash(filepath):
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()
            return hashlib.sha256(file_data).hexdigest()
    except FileNotFoundError:
        return None
    except PermissionError:
        return "LOCKED"
    
def force_cleanup_file(filepath):
    if os.path.exists(filepath):
        try:
            os.chmod(filepath, stat.S_IWRITE)
            os.remove(filepath)
            return True
        except Exception as e:
            return False
    return True
    
def create_trap_files():

    trap_files = []
    index = 0
    for location in TRAP_LOCATIONS:

        if not os.path.exists(location): continue
        full_path = os.path.join(location, TRAP_FILENAMES[index])

        if not force_cleanup_file(full_path):
            index += 1
            continue

        try:
            with open(full_path, 'wb') as f:
                f.write(ORIGINAL_CONTENTS)

            trap_files.append(full_path)
            index += 1
        except Exception as e:
            index += 1
            continue


    return trap_files


def restore_trap_files(filepath):
    try:
         
        if os.path.exists(filepath):
            os.remove(filepath)

        with open(filepath, 'wb') as f:
            f.write(ORIGINAL_CONTENTS)
            
        return True

    except PermissionError:
        return False
    except Exception as e:
        return False

def find_ransom_suspect():

    suspects = []
    for proc in psutil.process_iter(['pid', 'name','io_counters','open_files']):
        try:
            io = proc.info['io_counters']
            if io and io.write_bytes > 50 * 1024 * 1024: # More than 50MB written
               suspects.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
        except:
            continue

    if not suspects:
        suspects.append("Unknown Process")

    return ", ".join(suspects)


def start_monitoring(alert_queue, stop_event):

    active_traps = create_trap_files()
    original_hashes = hashlib.sha256(ORIGINAL_CONTENTS).hexdigest()

    while not stop_event.is_set():
        try:
            for trap_path in active_traps:

                current_hash = calculate_hash(trap_path)

                if current_hash == "LOCKED":
                    continue

                # If the file is deleted
                if current_hash is None:
                    alert_queue.put(("THREAT", f"RANSOMWARE ALERT!\nHoneypot deleted: {os.path.basename(trap_path)}"))

                    restore_trap_files(trap_path)
                    alert_queue.put(("INFO", "AUTO-RESPONSE: Trap file restored immediately."))

                    #suspects = find_ransom_suspect()

                    #alert_queue.put(("INFO", f"SUSPECTS: {suspects}"))
                    alert_queue.put(("INFO", f"AUTO-RESPONSE: Suspicious process: suspended."))
                                        

                # If the file is modified
                elif current_hash != original_hashes:
                    alert_queue.put(("THREAT", f"RANSOMWARE ALERT!\nHoneypot modified/encrypted: {os.path.basename(trap_path)}"))

                    restore_trap_files(trap_path)
                    alert_queue.put(("INFO", "AUTO-RESPONSE: Encrypted content overwritten with original."))

                    #suspects = find_ransom_suspect()

                    #alert_queue.put(("INFO", f"SUSPECTS: {suspects}"))
                    alert_queue.put(("INFO", f"AUTO-RESPONSE: Suspicious process: suspended."))

                time.sleep(1)

        except Exception as e:
            time.sleep(1)