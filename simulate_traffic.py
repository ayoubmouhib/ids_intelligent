import time
import random
import requests

API_URL = "http://127.0.0.1:8000/predict"

SOURCE_IPS = ["10.0.2.15", "192.168.1.50", "172.16.0.4", "45.33.32.156", "185.220.101.5"]
DEST_IPS = ["192.150.187.43", "10.0.0.1", "192.168.1.1", "10.0.2.1"]
SERVICES = ["http", "dns", "ssl", "smtp", "ssh"]

def generate_sample():
    is_attack = random.random() < 0.35  # 35% chance of simulating an attack
    
    src_ip = random.choice(SOURCE_IPS)
    dst_ip = random.choice(DEST_IPS)
    service = random.choice(SERVICES)

    meta = {
        "timestamp": time.time(),
        "uid": f"C{random.randint(10000, 99999)}",
        "source_ip": src_ip,
        "source_port": random.randint(1024, 65535),
        "destination_ip": dst_ip,
        "destination_port": 80 if service == "http" else (443 if service == "ssl" else 22),
        "connection_state": "S0" if is_attack else "SF",
        "source_packets": random.randint(50, 5000) if is_attack else random.randint(5, 30),
        "destination_packets": random.randint(0, 10) if is_attack else random.randint(5, 50),
    }

    if is_attack:
        features = {
            "duration": round(random.uniform(0.01, 0.5), 3),
            "protocol_type": "tcp",
            "service": service,
            "flag": "S0",
            "src_bytes": random.randint(10000, 500000),
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 3,
            "num_failed_logins": random.randint(1, 5),
            "logged_in": 0,
            "num_compromised": 1,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": random.randint(100, 500),
            "srv_count": random.randint(100, 500),
            "serror_rate": 1.0,
            "srv_serror_rate": 1.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 255,
            "dst_host_srv_count": random.randint(1, 50),
            "dst_host_same_srv_rate": 0.9,
            "dst_host_diff_srv_rate": 0.1,
            "dst_host_same_src_port_rate": 0.8,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 1.0,
            "dst_host_srv_serror_rate": 1.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0,
        }
    else:
        features = {
            "duration": round(random.uniform(0.1, 10.0), 3),
            "protocol_type": "tcp",
            "service": service,
            "flag": "SF",
            "src_bytes": random.randint(200, 2000),
            "dst_bytes": random.randint(1000, 20000),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": random.randint(1, 10),
            "srv_count": random.randint(1, 10),
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
            "srv_rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": random.randint(1, 50),
            "dst_host_srv_count": random.randint(1, 50),
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.1,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0,
        }

    # Combine features and metadata at root level, while preserving sub-dicts for backward compatibility
    return {
        **features,
        **meta,
        "meta": meta,
        "features": features
    }

print("🚀 Starting IDS Network Traffic Simulator...")
print("Press Ctrl+C to stop.\n")

try:
    while True:
        payload = generate_sample()
        res = requests.post(API_URL, json=payload)
        if res.status_code == 200:
            data = res.json()
            decision = data.get("decision", data.get("prediction", "UNKNOWN"))
            rf = data.get("rf_probability", data.get("confidence", 0))
            src = payload.get("source_ip", payload.get("src_ip", "N/A"))
            dst = payload.get("destination_ip", payload.get("dst_ip", "N/A"))
            print(f" Flow [{src} -> {dst}] | Decision: {decision} | RF Prob: {rf:.2%}")
        else:
            print(f"❌ Error {res.status_code}: {res.text}")
        
        time.sleep(random.uniform(1.5, 3.5))
except KeyboardInterrupt:
    print("\nSimulator stopped.")
