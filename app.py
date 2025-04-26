# server.py
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta
import base64
import os
import random
import string
from crypto_utils import encrypt_puf, decrypt_puf, generate_mac, verify_mac, hash_puf
import hashlib
import json

app = Flask(__name__)
SECRET_KEY = b'supersecurekey_here_is_32_byte_l'

if not os.path.exists('logs'):
    os.makedirs('logs')

@app.before_request
def before_any_request():
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "method": request.method,
        "url": request.url,
        "remote_addr": request.remote_addr,
        "headers": {key: value for key, value in request.headers if key != 'Host'},
        "body": None
    }
    try:
        log_data["body"] = request.get_json()
    except Exception:
        log_data["body"] = request.data.decode('utf-8')  # fallback for non-JSON
    
    # Pretty print to console
    print(f"\n[DEBUG] Incoming Request:\n{json.dumps(log_data, indent=2)}\n" + "-"*80)
    
    # Save to a new file
    with open('logs/incoming_requests.jsonl', 'a') as f:
        f.write(json.dumps(log_data) + "\n")


# Initialize database
def init_db():
    try:
        print("[DEBUG] Initializing database...")
        conn = sqlite3.connect("sensor_data3.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS sensor_data (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                            temperature REAL,
                            humidity REAL,
                            rfid TEXT
                         )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS device_keys (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            device_name TEXT NOT NULL,
                            puf_key TEXT NOT NULL,
                            puf_hash TEXT NOT NULL,
                            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                         )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS used_nonces (
                            nonce TEXT PRIMARY KEY,
                            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS challenges (
                device_name TEXT PRIMARY KEY,
                challenge TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                        )''')
        conn.commit()
        print("[DEBUG] Database initialized successfully")
    except sqlite3.Error as e:
        print(f"[ERROR] Database initialization failed: {e}")

init_db()

def get_latest_puf_key(device_name):
    try:
        conn = sqlite3.connect("sensor_data3.db")
        cursor = conn.cursor()
        cursor.execute("""
            SELECT puf_key FROM device_keys
            WHERE device_name = ?
            ORDER BY id DESC LIMIT 1
        """, (device_name,))
        result = cursor.fetchone()
        return result[0] if result else None
    except sqlite3.Error as e:
        print(f"[ERROR] Database error in get_latest_puf_key: {e}")
        return None

# Chaotic map (logistic map)
def logistic_map(r, x, iterations):
    try:
        print(f"[DEBUG] Running logistic map with r={r}, x={x}, iterations={iterations}")
        for i in range(iterations):
            x = r * x * (1 - x)
        print(f"[DEBUG] Final x={x}")
        return x
    except Exception as e:
        print(f"[ERROR] Logistic map calculation failed: {e}")
        raise

# Decrypt data
def chaotic_decrypt(encrypted_data, puf_key):
    try:
        print(f"[DEBUG] Starting decryption with data type {type(encrypted_data)}, puf_key='{puf_key}'")
        # Convert Base64-decoded bytes to hex string
        encrypted_ascii = encrypted_data.decode('ascii')
        print(f"[DEBUG] Converted bytes to ASCII: '{encrypted_ascii}'")
        
        # Convert hex string to bytes
        encrypted_bytes = bytes.fromhex(encrypted_ascii)
        print(f"[DEBUG] Converted ASCII hex to bytes, length={len(encrypted_bytes)}")
        
        key_value = int(puf_key, 16)
        r = 3.5  # Fixed R-value
        x = 0.5  # Fixed initial condition
        decrypted = ""
        
        print(f"[DEBUG] Fixed R-value: {r}")
        for i in range(len(encrypted_bytes)):
            x = logistic_map(r, x, 10)
            chaotic_byte = int(x * 255)
            # Reverse the encryption: XOR with PUF key first, then chaotic byte
            decrypted_byte = (encrypted_bytes[i] ^ key_value) ^ chaotic_byte
            decrypted += chr(decrypted_byte)
            
            if i < 5:  # Limit debug output
                print(f"[DEBUG] Byte {i}: Encrypted={encrypted_bytes[i]}, PUF={key_value}, Chaotic={chaotic_byte}, Decrypted={ord(decrypted[-1])}")
        
        print(f"[DEBUG] Decrypted data: '{decrypted}'")
        return decrypted
    except ValueError as e:
        print(f"[ERROR] Invalid format: {e}")
        raise
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        raise
@app.route('/check_key', methods=['POST'])
def check_key():
    print("[DEBUG] /check_key endpoint hit")
    conn = sqlite3.connect("sensor_data3.db")
    cursor = conn.cursor()
    data = request.get_json()
    print(f"[DEBUG] Received data: {data}")

    device_name = data.get('device_name')
    puf_hash = data.get('puf_hash')
    nonce = data.get('nonce')
    mac = data.get('mac')

    print(f"[DEBUG] Checking nonce: {nonce}")
    if is_nonce_used(nonce):
        print("[DEBUG] Nonce replay detected")
        return jsonify({'message': 'Nonce replay detected'}), 403

    mac_data = (device_name + puf_hash + nonce).encode()
    print(f"[DEBUG] Verifying MAC for data: {mac_data}")
    if not verify_mac(mac_data, mac):
        print("[DEBUG] MAC verification failed")
        return jsonify({'message': 'MAC verification failed'}), 400

    print(f"[DEBUG] Querying database for device: {device_name}, puf_hash: {puf_hash}")
    cursor.execute('SELECT * FROM device_keys WHERE device_name = ? AND puf_hash = ?', 
                   (device_name, puf_hash))
    if cursor.fetchone():
        print("[DEBUG] PUF key exists for device")
        return jsonify({'message': 'PUF key exists'}), 200
    else:
        print("[DEBUG] PUF key not found for device")
        return jsonify({'message': 'PUF key not found'}), 404


# Generate challenge string
def generate_challenge():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# Calculate expected response
def calculate_expected_response(challenge):
    # Create a one-time pad by hashing challenge with key
    challenge_bytes = challenge.encode('utf-8')
    hash_input = challenge_bytes + SECRET_KEY
    one_time_pad = hashlib.sha256(hash_input).digest()
    
    # XOR the challenge with the one-time pad
    response_bytes = bytes(c ^ p for c, p in zip(challenge_bytes, one_time_pad))
    return response_bytes.hex()[:16]  # Return first 16 chars of hex representation

# Store nonce and check replay
def is_nonce_used(nonce):
    conn = sqlite3.connect("sensor_data3.db")
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM used_nonces WHERE nonce = ?', (nonce,))
    if cursor.fetchone():
        return True
    cursor.execute('INSERT INTO used_nonces (nonce, timestamp) VALUES (?, ?)', 
                   (nonce, str(datetime.now())))
    conn.commit()
    return False

@app.route('/generate_challenge', methods=['POST']) 
def generate_challenge_for_device():
    print("[DEBUG] /generate_challenge endpoint hit")
    conn = sqlite3.connect("sensor_data3.db")
    cursor = conn.cursor()
    data = request.get_json()
    print(f"[DEBUG] Received data: {data}")

    device_name = data.get('device_name')
    challenge = generate_challenge()
    timestamp = datetime.now().isoformat()

    print(f"[DEBUG] Generated challenge '{challenge}' for device '{device_name}' at '{timestamp}'")

    cursor.execute('REPLACE INTO challenges (device_name, challenge, timestamp, status) VALUES (?, ?, ?, ?)',
                   (device_name, challenge, timestamp, "ACTIVE"))
    conn.commit()
    print("[DEBUG] Challenge stored in database successfully")
    return jsonify({'challenge': challenge}), 200

@app.route('/register_key', methods=['POST'])
def register_key():
    print("[DEBUG] /register_key endpoint hit")
    conn = sqlite3.connect("sensor_data3.db")
    cursor = conn.cursor()
    data = request.get_json()
    print(f"[DEBUG] Received data: {data}")

    device_name = data.get('device_name')
    challenge_response = data.get('challenge_response')
    nonce = data.get('nonce')
    encrypted_key = data.get('encrypted_key')
    puf_hash = data.get('puf_hash')
    mac = data.get('mac')

    print(f"[DEBUG] Checking nonce: {nonce}")
    if is_nonce_used(nonce):
        print("[DEBUG] Nonce replay detected")
        return jsonify({'message': 'Nonce replay detected'}), 403

    print(f"[DEBUG] Fetching latest challenge for device: {device_name}")
    cursor.execute('SELECT challenge, timestamp, status FROM challenges WHERE device_name = ? ORDER BY timestamp DESC LIMIT 1', (device_name,))
    result = cursor.fetchone()

    if not result:
        print("[DEBUG] No challenge found for device")
        return jsonify({'message': 'Challenge not generated'}), 400

    challenge, timestamp, status = result
    print(f"[DEBUG] Latest challenge: {challenge}, timestamp: {timestamp}, status: {status}")

    challenge_time = datetime.fromisoformat(timestamp)
    current_time = datetime.now()
    max_age = timedelta(minutes=5)

    if current_time - challenge_time > max_age:
        print("[DEBUG] Challenge expired")
        cursor.execute('UPDATE challenges SET status = ? WHERE device_name = ?', ('EXPIRED', device_name))
        conn.commit()
        return jsonify({'message': 'Challenge expired'}), 401

    if status != 'ACTIVE':
        print("[DEBUG] Challenge is not active")
        return jsonify({'message': 'Challenge not active'}), 401

    expected_response = calculate_expected_response(challenge)
    print(f"[DEBUG] Expected challenge response: {expected_response}")

    if challenge_response != expected_response:
        print("[DEBUG] Challenge response validation failed")
        cursor.execute('UPDATE challenges SET status = ? WHERE device_name = ?', ('INACTIVE', device_name))
        conn.commit()
        return jsonify({'message': 'Challenge-Response Failed'}), 401

    print("[DEBUG] Challenge response validation successful")
    cursor.execute('UPDATE challenges SET status = ? WHERE device_name = ?', ('USED', device_name))
    conn.commit()

    mac_data = (device_name + challenge_response + nonce + encrypted_key + puf_hash).encode()
    print(f"[DEBUG] Verifying MAC for data: {mac_data}")
    if not verify_mac(mac_data, mac):
        print("[DEBUG] MAC verification failed after challenge validation")
        return jsonify({'message': 'MAC verification failed'}), 400

    print(f"[DEBUG] Starting PUF key decryption with encrypted_key='{encrypted_key}'")
    puf_key = decrypt_puf(*encrypted_key.split(":"))
    print(f"[DEBUG] Decrypted PUF key: '{puf_key}'")

    timestamp = datetime.now().isoformat()
    print(f"[DEBUG] Inserting PUF key into device_keys table for device '{device_name}' at '{timestamp}'")
    cursor.execute('INSERT INTO device_keys (device_name, puf_key, puf_hash, timestamp) VALUES (?, ?, ?, ?)',
                   (device_name, puf_key, puf_hash, timestamp))
    conn.commit()
    print("[DEBUG] PUF key registered successfully")
    return jsonify({'message': 'PUF key registered successfully'}), 200

@app.route('/receive_data', methods=['POST'])
def receive_data():
    try:
        conn = sqlite3.connect("sensor_data3.db")
        cursor = conn.cursor()
        data = request.get_json()
        print(f"[DEBUG] Received receive_data request with data: {data}")
        if not data or 'data' not in data:
            print("[ERROR] Invalid JSON or missing 'key'/'data' in request")
            return jsonify({"error": "Invalid JSON or missing key/data"}), 400
        
        puf_key = get_latest_puf_key(device_name=data.get('device_name'))
        if not puf_key:
            print("[ERROR] No PUF key found in database")
            return jsonify({"error": "No PUF key found"}), 400
        base64_data = data['data']
        print(f"[DEBUG] Processing key: '{puf_key}', base64_data: '{base64_data}'")
        
        device_name = data.get('device_name')
        nonce = data.get('nonce')
        mac = data.get('mac')

        if is_nonce_used(nonce):
            return jsonify({'message': 'Nonce replay detected'}), 403

        mac_data = (device_name + base64_data + nonce).encode()
        if not verify_mac(mac_data, mac):
            return jsonify({'message': 'MAC verification failed'}), 400
        
        try:
            encrypted_bytes = base64.b64decode(base64_data)
            print(f"[DEBUG] Base64 decoded bytes (len={len(encrypted_bytes)}): {encrypted_bytes.hex()}")
        except base64.binascii.Error as e:
            print(f"[ERROR] Base64 decoding failed: {e}")
            return jsonify({"error": "Invalid Base64 data"}), 400
        
        decrypted_data = chaotic_decrypt(encrypted_bytes, puf_key)
        print(f"[DEBUG] Splitting decrypted data: '{decrypted_data}'")
        
        try:
            temp, humidity, rfid = decrypted_data.split(',')
            temp = float(temp)
            humidity = float(humidity)
            print(f"[DEBUG] Parsed values - Temp: {temp}, Humidity: {humidity}, RFID: '{rfid}'")
        except ValueError as e:
            print(f"[ERROR] Invalid sensor data format: {e}")
            return jsonify({"error": "Invalid sensor data format"}), 400
        
        timestamp = datetime.now().isoformat()
        cursor.execute("INSERT INTO sensor_data (timestamp, temperature, humidity, rfid) VALUES (?, ?, ?, ?)",
                       (timestamp, temp, humidity, rfid))
        conn.commit()
        print(f"[DEBUG] Sensor data stored successfully at timestamp: {timestamp}")
        
        return jsonify({"status": "data received", "decrypted": decrypted_data}), 200
    except sqlite3.Error as e:
        print(f"[ERROR] Database error in receive_data: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in receive_data: {e}")
        return jsonify({"error": "Internal server error"}), 500

def fetch_sensor_data():
    conn = sqlite3.connect("sensor_data3.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, temperature, humidity, rfid FROM sensor_data ORDER BY id DESC")
    data = cursor.fetchall()
    return data


def fetch_all_data():
    conn = sqlite3.connect("sensor_data3.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sensor_data")
    data = cursor.fetchall()
    return data

# Fetch encryption details (mock example, adjust as needed)
def fetch_encryption_steps():
    return [
        {"step": "Raw Data", "value": "25.3, 60, ABC123"},
        {"step": "XOR with PUF", "value": "Encrypted Hex: 3a4b5c"},
        {"step": "Base64 Encoding", "value": "U2Vuc29yRGF0YQ=="},
        {"step": "Transmission", "value": "Sent to server"},
        {"step": "Decryption", "value": "Recovered Data: 25.3, 60, ABC123"}
    ]

@app.route('/')
def index():
    sensor_data = fetch_sensor_data()
    encryption_steps = fetch_encryption_steps()
    return render_template('index.html', sensor_data=sensor_data, encryption_steps=encryption_steps)


@app.route('/data')
def data():
    return jsonify(fetch_all_data())

if __name__ == '__main__':
    print("[DEBUG] Starting Flask server...")
    app.run(host='0.0.0.0', port=5000)