from flask import Flask, request, jsonify
import sqlite3
from datetime import datetime
import base64
import json

app = Flask(__name__)
PUF_KEY = "0101000111001011000000000000000001110111000000001011101110000000"

# Initialize database
def init_db():
    conn = sqlite3.connect("sensor_data.db")
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
                        puf TEXT
                     )''')
    conn.commit()
    conn.close()

init_db()

def generate_r_from_puf(puf_key):
    hash_value = sum(ord(char) * 31**i for i, char in enumerate(puf_key)) % 300
    return 3.7 + (hash_value * 0.001)  # Normalize to [3.7, 4.0]

import base64

def chaotic_decrypt(ciphertext, puf_key):
    x = 0.5
    r = 3.7
    print("Decryption r:", r)

    try:
        decoded_bytes = base64.b64decode(ciphertext).decode()
        print("Decoded Bytes:", decoded_bytes)
    except Exception as e:
        return f"Base64 Decode Error: {e}"

    decrypted_bytes = bytearray()
    for i, byte in enumerate(decoded_bytes):
        x = r * x * (1 - x)
        chaotic_byte = int(x * 255) & 0xFF  # Ensure it stays in byte range
        decrypted_byte = byte ^ chaotic_byte
        decrypted_bytes.append(decrypted_byte)

        # Debugging:
        print(f"Index {i}: Byte {byte}, Chaotic Byte {chaotic_byte}, Decrypted {decrypted_byte}")

    print("Raw Decrypted Bytes:", decrypted_bytes)

    # Validate UTF-8
    try:
        plaintext = decrypted_bytes.decode('utf-8')
        print("Decrypted Data:", plaintext)
        return plaintext
    except UnicodeDecodeError as e:
        print(f"Unicode Decode Error: {e}. Raw Decrypted Bytes: {repr(decrypted_bytes)}")
        return f"Unicode Decode Error: {e}"


def get_latest_puf_key():
    conn = sqlite3.connect("sensor_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT puf FROM puf ORDER BY id DESC LIMIT 1")  # Get latest PUF key
    result = cursor.fetchone()
    conn.close()
    
    return result[0] if result else None


@app.route('/data', methods=['POST'])
def receive_data():
    try:
        test_string = "Hello, Base64!"
        encoded = base64.b64encode(test_string.encode()).decode()
        print("Encoded:", encoded)

        decoded = base64.b64decode(encoded).decode()
        print("Decoded:", decoded)
        print("Received Raw Data:", request.json.get("encrypted_data"))
        encrypted_data = request.json.get("encrypted_data")
        puf_key = get_latest_puf_key()  # Retrieve latest PUF key
        if not puf_key:
            return jsonify({"error": "No PUF key found"}), 500

        # decrypted_data = chaotic_decrypt(encrypted_data, PUF_KEY)
        decrypted_data = base64.b64decode(encrypted_data).decode()
        print(decrypted_data)
        try:
            data = json.loads(decrypted_data)  # ✅ Safe and correct
        except json.JSONDecodeError as e:
            return jsonify({"error": f"JSON Decode Error: {e}"}), 500

        temperature = data.get('temperature')
        humidity = data.get('humidity')
        rfid = data.get('rfid')

        if temperature is None or humidity is None or rfid is None:
            return jsonify({"error": "Invalid data"}), 400

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect("sensor_data.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO sensor_data (timestamp, temperature, humidity, rfid) VALUES (?, ?, ?, ?)", 
                       (timestamp, temperature, humidity, rfid))
        conn.commit()
        conn.close()

        return jsonify({"message": "Data received successfully"}), 200

    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/puf', methods=['POST'])
def receive_puf_data():
    try:
        data = request.json
        puf = data.get('puf')

        if puf is None:
            return jsonify({"error": "Invalid data"}), 400

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect("sensor_data.db")
        cursor = conn.cursor()

        # Check if PUF already exists
        cursor.execute("SELECT * FROM puf WHERE puf = ?", (puf,))
        existing_puf = cursor.fetchone()

        if existing_puf:
            conn.close()
            return jsonify({"message": "PUF already exists"}), 200

        # Insert new PUF
        cursor.execute("INSERT INTO puf (timestamp, puf) VALUES (?, ?)", 
                       (timestamp, puf))
        conn.commit()
        conn.close()

        return jsonify({"message": "PUF stored successfully"}), 200

    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route('/data', methods=['GET'])
def get_data():
    conn = sqlite3.connect("sensor_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sensor_data")
    data = cursor.fetchall()
    conn.close()
    
    return jsonify({"data": data}), 200

@app.route('/puf', methods=['GET'])
def get_puf_data():
    conn = sqlite3.connect("sensor_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM puf")
    data = cursor.fetchall()
    conn.close()
    
    return jsonify({"data": data}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
