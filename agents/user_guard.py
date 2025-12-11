import time
import math
import statistics
import os
import json
import ctypes
from pynput import mouse, keyboard

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILE_PATH = os.path.join(BASE_DIR, 'data', 'user_profile.json')

LEARNING_DURATION = 5*60  # 5 minutes
LOCK_SCORE = 100

W_VELOCITY = 0.4
W_ACCELERATION = 0.4
W_ANGLES = 0.2
W_PRESS = 1.0
W_FLIGHT = 3.0

state = {
    #mouse
    "mouse_records": [],      # raw data(x, y, time)
    "mouse_stats": {          # precomputed statistics
        "velocities": [],
        "accelerations": [],
        "angles": []
    },
    
    # keyboard
    "active_keys": {},        # which keys are currently pressed
    "last_key_time": None,   
    "key_stats": {
        "press_times": [],
        "flight_times": []
    },
    
    "profile": None          # loaded user profile
}


#******************* Phisycs and Math Functions *******************#

def calc_distance(p1, p2):
    return math.sqrt((p2[0] - p1[0])**2 + (p2[1] - p1[1])**2)

def calc_velocity(dist, dt):
    return dist / dt if dt > 0 else 0

def calc_acceleration(v1, v2, dt):
    return (v2 - v1) / dt if dt > 0 else 0

def calc_angle(p1, p2):
    return math.atan2(p2[1] - p1[1], p2[0] - p1[0])

def calc_z_score(val, mean, std):
    if std == 0: return 0
    return abs(val - mean) / std


#******************* Listeners *******************#

def on_move(x, y):
    t = time.time()
    state["mouse_records"].append((x, y, t))

    if len(state["mouse_records"]) >= 3:
        p1 = state["mouse_records"][-1]
        p2 = state["mouse_records"][-2]
        p3 = state["mouse_records"][-3]

        dist1 = calc_distance((p1[0], p1[1]), (p2[0], p2[1]))
        dist2 = calc_distance((p2[0], p2[1]), (p3[0], p3[1]))

        dt1 = p1[2] - p2[2] 
        dt2 = p2[2] - p3[2]

        if dt1 <= 0 or dt2 <= 0:
            return

        v1 = calc_velocity(dist1, dt1)
        v2 = calc_velocity(dist2, dt2)
        a = calc_acceleration(v2, v1, dt1)
        angle = calc_angle((p2[0], p2[1]), (p3[0], p3[1]))

        state["mouse_stats"]["velocities"].append(abs(v2))
        state["mouse_stats"]["accelerations"].append(abs(a))
        state["mouse_stats"]["angles"].append(abs(angle))

        if len(state["mouse_records"]) > 100:
            state["mouse_records"].pop(0)

def on_press(key):
    t = time.time()
    try: k = key.char
    except: k = str(key)
    state["active_keys"][k] = t

    if state["last_key_time"] is not None:
        flight_time = t - state["last_key_time"]
        if 0 < flight_time < 4.0:
            state["key_stats"]["flight_times"].append(flight_time)


def on_release(key):
    t = time.time()
    try: k = key.char
    except: k = str(key)

    if k in state["active_keys"]:
        press_time = t - state["active_keys"][k]
        if 0 < press_time < 4.0:
            state["key_stats"]["press_times"].append(press_time)
        del state["active_keys"][k]

    state["last_key_time"] = t


def save_profile():

    mouse_velocities = state["mouse_stats"]["velocities"]
    mouse_accelerations = state["mouse_stats"]["accelerations"]
    mouse_angles = state["mouse_stats"]["angles"]
    key_press_times = state["key_stats"]["press_times"]
    key_flight_times = state["key_stats"]["flight_times"]

    if len(mouse_velocities) < 10 or len(key_press_times) < 10:
        print("[UserGuard] Not enough data collected to create profile.")
        return
    
    profile = {
        "mouse": {
            "velocity_mean": statistics.mean(mouse_velocities),
            "velocity_std": statistics.stdev(mouse_velocities),
            "acceleration_mean": statistics.mean(mouse_accelerations),
            "acceleration_std": statistics.stdev(mouse_accelerations),
            "angle_mean": statistics.mean(mouse_angles),
            "angle_std": statistics.stdev(mouse_angles)
        },
        "keyboard": {
            "press_mean": statistics.mean(key_press_times),
            "press_std": statistics.stdev(key_press_times),
            "flight_mean": statistics.mean(key_flight_times),
            "flight_std": statistics.stdev(key_flight_times)
        }
    }

    for category in profile.values():
        for key , value in category.items():
            if "std" in key and value == 0:
                category[key] = 0.0001  # prevent division by zero

    with open(PROFILE_PATH, 'w') as f:
        json.dump(profile, f, indent=4)

    state["profile"] = profile
    state["mouse_stats"] = {"velocities": [], "accelerations": [], "angles": []}
    state["key_stats"] = {"press_times": [], "flight_times": []}
    print("[UserGuard] User profile saved.")
    return True


def load_profile():
    if os.path.exists(PROFILE_PATH):
        try:
            with open(PROFILE_PATH, "r") as f:
                state["profile"] = json.load(f)
            return True
        except: return False
    return False



#******************* Main Functions *******************#

def check_behavior():
    profile = state["profile"]
    if profile is None:
        print("[UserGuard] No user profile loaded.")
        return 0

    score = 0

    # Mouse Analysis
    mouse_data = state["mouse_stats"]
    if len(mouse_data["velocities"]) > 5:

        current_velocity = statistics.mean(mouse_data["velocities"])
        current_acceleration = statistics.mean(mouse_data["accelerations"])
        current_angle = statistics.mean(mouse_data["angles"])

        velocity_z = calc_z_score(current_velocity, profile["mouse"]["velocity_mean"], profile["mouse"]["velocity_std"])
        acceleration_z = calc_z_score(current_acceleration, profile["mouse"]["acceleration_mean"], profile["mouse"]["acceleration_std"])
        angle_z = calc_z_score(current_angle, profile["mouse"]["angle_mean"], profile["mouse"]["angle_std"])

        total_mouse_score = (W_VELOCITY * velocity_z) + (W_ACCELERATION * acceleration_z) + (W_ANGLES * angle_z)

        if total_mouse_score > 2.0:
            score += 40

        state["mouse_stats"] = {"velocities": [], "accelerations": [], "angles": []}

    # Keyboard Analysis
    key_data = state["key_stats"]
    if len(key_data["press_times"]) > 5:

        current_press = statistics.mean(key_data["press_times"])
        current_flight = statistics.mean(key_data["flight_times"])

        press_z = calc_z_score(current_press, profile["keyboard"]["press_mean"], profile["keyboard"]["press_std"])
        flight_z = calc_z_score(current_flight, profile["keyboard"]["flight_mean"], profile["keyboard"]["flight_std"])

        total_key_score = (W_PRESS * press_z) + (W_FLIGHT * flight_z)

        if total_key_score > 3.0:
            score += 60

        state["key_stats"] = {"press_times": [], "flight_times": []}

    return score


def lock_pc():
    ctypes.windll.user32.LockWorkStation()


def start_monitoring(alert_queue, stop_event):
    
    mouse_listener = mouse.Listener(on_move=on_move)
    keyboard_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    mouse_listener.start()
    keyboard_listener.start()

    mode = "LEARN"
    if load_profile():
        mode = "PROTECT"
        print("[UserGuard] User profile loaded. Starting monitoring...")

    else:
        print("[UserGuard] No profile found. Starting learning phase...")
        start_learn = time.time()

    suspicion_score = 0

    while not stop_event.is_set():
        try:
            if mode == "LEARN":
                if time.time() - start_learn > LEARNING_DURATION:
                    if save_profile():
                        mode = "PROTECT"
                        alert_queue.put(("INFO", "UserGuard: Profile built. Protection ACTIVE."))
                    else:
                        start_learn = time.time()
                time.sleep(1)

            elif mode == "PROTECT":
                anomaly_score = check_behavior()

                if anomaly_score > 0:
                    suspicion_score += anomaly_score
                    print(f"[UserGuard] Anomaly detected! Current suspicion score: {suspicion_score}")

                    if suspicion_score >= LOCK_SCORE:
                        alert_queue.put(("THREAT", "USER IDENTITY THEFT DETECTED!\nLocking System."))
                        lock_pc()
                        suspicion_score = 0
                        time.sleep(10)
                else:
                    if suspicion_score > 0:
                        suspicion_score -= 5
                time.sleep(2)

        except Exception as e:
            print(f"[UserGuard] Error in monitoring loop: {e}")
            time.sleep(2)

    mouse_listener.stop()
    keyboard_listener.stop()

        
def creat_profile():
    print("[UserGuard] Starting profile creation...")
    mouse_listener = mouse.Listener(on_move=on_move)
    keyboard_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    mouse_listener.start()
    keyboard_listener.start()

    start_time = time.time()
    while time.time() - start_time < LEARNING_DURATION:
        time.sleep(1)

    if save_profile():
        print("[UserGuard] Profile creation completed successfully.")
    else:
        print("[UserGuard] Profile creation failed.")

    mouse_listener.stop()
    keyboard_listener.stop()


if __name__ == "__main__":
    creat_profile()