from flask import Flask, request, jsonify, render_template
import base64
import sqlite3
from datetime import datetime
from flask_socketio import SocketIO
import time
import threading

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database
def init_db():
    try:
        print("[DEBUG] Initializing database...")
        conn = sqlite3.connect("sensor_data3.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS sensor_data (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT,
                            temperature REAL,
                            humidity REAL,
                            rfid TEXT
                         )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS puf (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT,
                            puf TEXT,
                            puf_hash TEXT
                         )''')
        conn.commit()
        print("[DEBUG] Database initialized successfully")
    except sqlite3.Error as e:
        print(f"[ERROR] Database initialization failed: {e}")
    finally:
        if 'conn' in locals():
            conn.close()
            print("[DEBUG] Database connection closed")

init_db()

def get_latest_puf_key():
    try:
        conn = sqlite3.connect("sensor_data3.db")
        cursor = conn.cursor()
        cursor.execute("SELECT puf FROM puf ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except sqlite3.Error as e:
        print(f"[ERROR] Database error in get_latest_puf_key: {e}")

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

@app.route('/check_key', methods=['GET'])
def check_key():
    try:
        key = request.args.get('key')
        print(f"[DEBUG] Checking key: '{key}'")
        if not key:
            print("[ERROR] No key provided in request")
            return jsonify({"error": "Key parameter missing"}), 400
        
        conn = sqlite3.connect("sensor_data3.db")
        cursor = conn.cursor()
        cursor.execute("SELECT puf FROM puf WHERE puf = ?", (key,))
        result = cursor.fetchone()
        
        if result:
            print(f"[DEBUG] Key '{key}' found in database")
            return "found", 200
        else:
            print(f"[DEBUG] Key '{key}' not found in database")
            return "not_found", 200
    except sqlite3.Error as e:
        print(f"[ERROR] Database error in check_key: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in check_key: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if 'conn' in locals():
            conn.close()
            print("[DEBUG] Database connection closed in check_key")

@app.route('/register_key', methods=['POST'])
def register_key():
    try:
        data = request.get_json()
        print(f"[DEBUG] Received register_key request with data: {data}")
        if not data or 'key' not in data:
            print("[ERROR] Invalid JSON or missing 'key' in request")
            return jsonify({"error": "Invalid JSON or missing key"}), 400
        
        key = data['key']
        timestamp = datetime.now().isoformat()
        print(f"[DEBUG] Registering key: '{key}' at timestamp: {timestamp}")
        
        conn = sqlite3.connect("sensor_data3.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO puf (timestamp, puf) VALUES (?, ?)", (timestamp, key))
        conn.commit()
        print(f"[DEBUG] Key '{key}' registered successfully")
        
        return jsonify({"status": "key registered"}), 200
    except sqlite3.Error as e:
        print(f"[ERROR] Database error in register_key: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in register_key: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if 'conn' in locals():
            conn.close()
            print("[DEBUG] Database connection closed in register_key")

@app.route('/receive_data', methods=['POST'])
def receive_data():
    try:
        data = request.get_json()
        print(f"[DEBUG] Received receive_data request with data: {data}")
        if not data or 'data' not in data:
            print("[ERROR] Invalid JSON or missing 'key'/'data' in request")
            return jsonify({"error": "Invalid JSON or missing key/data"}), 400
        
        puf_key = get_latest_puf_key()
        if not puf_key:
            print("[ERROR] No PUF key found in database")
            return jsonify({"error": "No PUF key found"}), 400
        base64_data = data['data']
        print(f"[DEBUG] Processing key: '{puf_key}', base64_data: '{base64_data}'")
        
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
        conn = sqlite3.connect("sensor_data3.db")
        cursor = conn.cursor()
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
    finally:
        if 'conn' in locals():
            conn.close()
            print("[DEBUG] Database connection closed in receive_data")

def fetch_sensor_data():
    conn = sqlite3.connect("sensor_data3.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, temperature, humidity, rfid FROM sensor_data ORDER BY id DESC")
    data = cursor.fetchall()
    conn.close()
    return data


def fetch_all_data():
    conn = sqlite3.connect("sensor_data3.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sensor_data")
    data = cursor.fetchall()
    conn.close()
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

def background_thread():
    while True:
        socketio.sleep(5)  # Proper sleep to avoid blocking
        data = fetch_sensor_data()
        formatted_data = [{"timestamp": d[0], "temperature": d[1], "humidity": d[2], "rfid": d[3]} for d in data]
        socketio.emit('update_data', formatted_data)


# Start the background thread
socketio.start_background_task(background_thread)

if __name__ == '__main__':
    print("[DEBUG] Starting Flask server...")
    app.run(host='0.0.0.0', port=5000)