#!/usr/bin/env python3
"""
Enhanced IoT Security Test System
This script tests security vulnerabilities in an IoT authentication system
"""
import requests
import logging
import json
import random
import string
import hashlib
import csv
import base64
import time
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

# Configuration
API_ENDPOINT = "http://192.168.29.128:5000"
DEVICE_NAMES = ["ESP32_01", "ESP32_02", "ESP32_03", "ESP32_04"]
DEFAULT_DEVICE = "ESP32_01"
DEFAULT_PUF_HASH = "44cb730c420480a0477b505ae68af508fb90f96cf0ec54c6ad16949dd427f13a"

# Set up logging
logging.basicConfig(
    filename='iot_security_tests.log', 
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("IoTSecurityTester")

# Reusable data storage for replay attacks
stored_nonces = {}
stored_requests = {}

def generate_nonce(length=12):
    """Generate a random nonce string."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def calculate_mac(data_string):
    """Calculate a MAC (Message Authentication Code) using SHA-256."""
    return hashlib.sha256(data_string.encode('utf-8')).hexdigest()

def encode_sensor_data(temp, humidity, rfid):
    """Simulate encryption of sensor data."""
    data_str = f"{temp},{humidity},{rfid}"
    # This simulates what your ESP32 would do with encrypted data
    return base64.b64encode(data_str.encode('utf-8')).decode('utf-8')

def execute_request(endpoint, payload, store_for_replay=False, attack_details=None):
    """Execute a request to the specified endpoint and log the results."""
    url = f"{API_ENDPOINT}/{endpoint}"
    
    try:
        logger.info(f"Sending request to {url}")
        logger.debug(f"Request payload: {json.dumps(payload)}")
        
        if attack_details:
            logger.info(f"Attack simulation: {attack_details['type']} - {attack_details['description']}")
            
        start_time = time.time()
        response = requests.post(url, json=payload, timeout=10)
        elapsed_time = time.time() - start_time
        
        logger.info(f"Response received in {elapsed_time:.3f}s: HTTP {response.status_code}")
        logger.debug(f"Response content: {response.text}")
        
        # Store this request for potential replay attacks
        if store_for_replay:
            device_name = payload.get('device_name', 'unknown')
            if device_name not in stored_requests:
                stored_requests[device_name] = {}
            stored_requests[device_name][endpoint] = payload
            
            # Store the nonce for replay attack testing
            if 'nonce' in payload:
                stored_nonces[device_name] = payload['nonce']
        
        return {
            "status_code": response.status_code,
            "response_data": response.json() if response.text else {},
            "elapsed_time": elapsed_time
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return {
            "status_code": 0,
            "response_data": {"error": str(e)},
            "elapsed_time": 0
        }

def authentication_flow(device_name, puf_hash, attack_type=None):
    """Perform the complete authentication flow for a device."""
    # 1. Check if device key exists
    check_key_result = check_device_key(device_name, puf_hash, attack_type)
    
    # 2. Generate challenge for the device
    challenge_result = generate_challenge(device_name, attack_type)
    
    # 3. Register device key with challenge response
    register_result = register_device_key(device_name, puf_hash, 
                                         challenge_result['response_data'].get('challenge', ''),
                                         attack_type)
    
    # Return consolidated results
    return {
        "check_key": check_key_result,
        "challenge": challenge_result,
        "register": register_result,
        "overall_status": (check_key_result['status_code'] == 200 and 
                          challenge_result['status_code'] == 200 and 
                          register_result['status_code'] == 200)
    }

def check_device_key(device_name, puf_hash, attack_type=None):
    """Test the check_key endpoint."""
    nonce = generate_nonce()
    
    # Prepare basic request
    payload = {
        "device_name": device_name,
        "puf_hash": puf_hash,
        "nonce": nonce
    }
    
    # Apply attack modifications if specified
    if attack_type:
        payload = apply_attack_modifications(payload, attack_type, "check_key")
    
    # Compute MAC after any modifications
    mac = calculate_mac(payload['device_name'] + payload['puf_hash'] + payload['nonce'])
    payload['mac'] = mac
    
    # Make the request
    return execute_request("check_key", payload, store_for_replay=True, 
                          attack_details={"type": attack_type, "description": get_attack_description(attack_type)})

def generate_challenge(device_name, attack_type=None):
    """Test the generate_challenge endpoint."""
    payload = {
        "device_name": device_name
    }
    
    # Apply attack modifications if specified
    if attack_type:
        payload = apply_attack_modifications(payload, attack_type, "generate_challenge")
    
    # Make the request
    return execute_request("generate_challenge", payload, 
                          attack_details={"type": attack_type, "description": get_attack_description(attack_type)})

def register_device_key(device_name, puf_hash, challenge, attack_type=None):
    """Test the register_key endpoint."""
    nonce = generate_nonce()
    
    # Simulate challenge response calculation (in a real device, this would use the PUF)
    challenge_response = hashlib.md5(challenge.encode()).hexdigest()[:16]
    
    # Simulate encrypted key generation (in a real system, this would be more complex)
    encrypted_key = f"{nonce}:p7//K5hIfk7IIOGSdFNZcpHi"
    
    # Prepare basic request
    payload = {
        "device_name": device_name,
        "challenge_response": challenge_response,
        "nonce": nonce,
        "encrypted_key": encrypted_key,
        "puf_hash": puf_hash
    }
    
    # Apply attack modifications if specified
    if attack_type:
        payload = apply_attack_modifications(payload, attack_type, "register_key")
    
    # Compute MAC after any modifications
    mac_data = (payload['device_name'] + payload['challenge_response'] + 
               payload['nonce'] + payload['encrypted_key'] + payload['puf_hash'])
    payload['mac'] = calculate_mac(mac_data)
    
    # Make the request
    return execute_request("register_key", payload, store_for_replay=True,
                          attack_details={"type": attack_type, "description": get_attack_description(attack_type)})

def send_sensor_data(device_name, temp, humidity, rfid, attack_type=None):
    """Test the receive_data endpoint."""
    nonce = generate_nonce()
    
    # Encode the sensor data (simulating encryption)
    encoded_data = encode_sensor_data(temp, humidity, rfid)
    
    # Prepare basic request
    payload = {
        "device_name": device_name,
        "data": encoded_data,
        "nonce": nonce
    }
    
    # Apply attack modifications if specified
    if attack_type:
        payload = apply_attack_modifications(payload, attack_type, "receive_data")
    
    # Compute MAC after any modifications
    mac = calculate_mac(payload['device_name'] + payload['data'] + payload['nonce'])
    payload['mac'] = mac
    
    # Make the request
    return execute_request("receive_data", payload, store_for_replay=True,
                          attack_details={"type": attack_type, "description": get_attack_description(attack_type)})

def apply_attack_modifications(payload, attack_type, endpoint):
    """Apply attack-specific modifications to the payload."""
    modified_payload = payload.copy()
    
    if attack_type == "Replay Attempt":
        # Reuse a nonce from a previous request if available
        device_name = payload.get('device_name', DEFAULT_DEVICE)
        if device_name in stored_nonces:
            modified_payload['nonce'] = stored_nonces[device_name]
            logger.info(f"Replay attack: Reusing nonce '{stored_nonces[device_name]}'")
    
    elif attack_type == "Delayed Replay":
        # Similar to replay but with a slight delay
        device_name = payload.get('device_name', DEFAULT_DEVICE)
        if device_name in stored_requests and endpoint in stored_requests[device_name]:
            # Use the entire stored request with a delay
            time.sleep(2)  # Add a delay to simulate time passing
            return stored_requests[device_name][endpoint]
    
    elif attack_type == "Payload Tampering":
        # Manipulate the payload but keep the MAC from the original
        if 'data' in modified_payload:
            # Tamper with sensor data
            modified_payload['data'] = encode_sensor_data(
                random.uniform(20, 30),  # Random temperature
                random.uniform(40, 60),  # Random humidity
                "TAMPERED_DATA"          # Tampered RFID
            )
        elif 'puf_hash' in modified_payload:
            # Slightly alter the hash to simulate tampering
            modified_payload['puf_hash'] = modified_payload['puf_hash'][:-2] + "ff"
    
    elif attack_type == "Authentication Failure":
        # Use incorrect authentication credentials
        if 'puf_hash' in modified_payload:
            modified_payload['puf_hash'] = hashlib.sha256(b"wrong_device_key").hexdigest()
        if 'challenge_response' in modified_payload:
            modified_payload['challenge_response'] = "incorrect_response"
    
    elif attack_type == "Forged ID":
        # Use a forged device ID
        modified_payload['device_name'] = f"FORGED_{modified_payload.get('device_name', DEFAULT_DEVICE)}"
    
    elif attack_type == "Unknown Device":
        # Use a completely unknown device identifier
        modified_payload['device_name'] = f"UNKNOWN_DEVICE_{random.randint(1000, 9999)}"
        if 'puf_hash' in modified_payload:
            modified_payload['puf_hash'] = hashlib.sha256(f"unknown_device_{random.randint(1000, 9999)}".encode()).hexdigest()
    
    elif attack_type == "MAC Forgery":
        # Generate an incorrect MAC
        if 'mac' in modified_payload:
            modified_payload['mac'] = hashlib.sha256(f"forged_data_{random.randint(1000, 9999)}".encode()).hexdigest()
    
    return modified_payload

def get_attack_description(attack_type):
    """Return a description of the attack type."""
    descriptions = {
        "Normal": "Valid device, valid data, new nonce, correct MAC.",
        "Replay Attempt": "The same old packet with the same nonce is sent again.",
        "Payload Tampering": "The transmitted data was altered after encryption.",
        "Authentication Failure": "Device fails authentication due to incorrect credentials.",
        "Delayed Replay": "Old valid data re-transmitted with delay.",
        "Forged ID": "An attacker forged a device ID.",
        "Unknown Device": "A completely unknown device attempts to authenticate.",
        "MAC Forgery": "The MAC is forged to try to bypass integrity checks.",
        None: "No attack simulation - normal operation."
    }
    return descriptions.get(attack_type, "Unknown attack type")

def process_test_results(results):
    """Process test results into a format suitable for the CSV report."""
    processed_results = []
    
    for result in results:
        auth_result = "✅ Success" if result.get("auth_success", False) else "❌ Failed"
        nonce_valid = "✅ New"
        mac_status = "✅ Verified"
        final_verdict = "✅ Accepted"
        
        # Check for specific error messages in responses
        check_key_response = result.get("check_key", {}).get("response_data", {})
        register_response = result.get("register", {}).get("response_data", {})
        
        if "Nonce replay detected" in str(check_key_response) or "Nonce replay detected" in str(register_response):
            nonce_valid = "❌ Reused"
            final_verdict = "❌ Rejected"
        
        if "MAC verification failed" in str(check_key_response) or "MAC verification failed" in str(register_response):
            mac_status = "❌ Tampered"
            final_verdict = "❌ Rejected"
        
        if result.get("attack_type") != "Normal" and not result.get("auth_success", False):
            final_verdict = "❌ Rejected"
        
        if result.get("attack_type") == "Unknown Device":
            nonce_valid = "❌ Unknown"
            mac_status = "❌ Invalid"
        
        processed_result = {
            "Device ID": result.get("device_name", "Unknown"),
            "Temp (°C)": result.get("temp", "N/A"),
            "Humidity (%)": result.get("humidity", "N/A"),
            "RFID": result.get("rfid", "N/A"),
            "Auth Result": auth_result,
            "Nonce Valid": nonce_valid,
            "MAC Status": mac_status,
            "Attack Type": result.get("attack_type", "Unknown"),
            "Final Verdict": final_verdict,
            "Response Code": result.get("response_code", 0),
            "Response Time (ms)": round(result.get("response_time", 0) * 1000)
        }
        
        processed_results.append(processed_result)
    
    return processed_results

def run_comprehensive_tests():
    """Run a comprehensive suite of tests against all endpoints."""
    all_results = []
    
    # Define test cases: (device_name, temp, humidity, rfid, attack_type)
    test_cases = [
        # Normal authentication flows (for reference)
        (DEFAULT_DEVICE, 25.7, 53.1, "A1B2C3", "Normal"),
        
        # Attack simulations
        (DEFAULT_DEVICE, 25.9, 52.9, "A1B2C3", "Replay Attempt"),
        ("ESP32_02", 26.0, 51.8, "C4D5E6", "Payload Tampering"),
        ("ESP32_03", 28.1, 60.2, "Z9X8Y7", "Unknown Device"),
        (DEFAULT_DEVICE, 26.1, 53.0, "A1B2C3", "Delayed Replay"),
        ("ESP32_04", 27.0, 55.5, "F1E2D3", "Forged ID"),
        (DEFAULT_DEVICE, 26.3, 54.1, "A1B2C3", "Authentication Failure"),
        (DEFAULT_DEVICE, 26.5, 54.8, "A1B2C3", "MAC Forgery")
    ]
    
    for device_name, temp, humidity, rfid, attack_type in test_cases:
        logger.info(f"\n{'=' * 60}\nExecuting test case: {attack_type} on {device_name}\n{'=' * 60}")
        
        # First authenticate
        auth_results = authentication_flow(device_name, DEFAULT_PUF_HASH, 
                                          None if attack_type == "Normal" else attack_type)
        
        # Then send sensor data (only for successfully authenticated devices)
        sensor_result = None
        if auth_results["overall_status"] or attack_type in ["Payload Tampering", "Replay Attempt", "Delayed Replay"]:
            sensor_result = send_sensor_data(device_name, temp, humidity, rfid, 
                                           None if attack_type == "Normal" else attack_type)
        
        # Compile results
        result = {
            "device_name": device_name,
            "temp": temp,
            "humidity": humidity,
            "rfid": rfid,
            "attack_type": attack_type,
            "auth_success": auth_results["overall_status"],
            "check_key": auth_results["check_key"],
            "challenge": auth_results["challenge"],
            "register": auth_results["register"],
            "sensor_data": sensor_result,
            "response_code": auth_results["check_key"]["status_code"],
            "response_time": auth_results["check_key"]["elapsed_time"]
        }
        
        all_results.append(result)
        
        # Brief delay between tests
        time.sleep(1)
    
    return all_results

def generate_reports(results):
    """Generate test reports in CSV format and visualizations."""
    # Process results
    processed_results = process_test_results(results)
    
    # Save to CSV
    csv_file = 'iot_security_test_results.csv'
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=processed_results[0].keys())
        writer.writeheader()
        writer.writerows(processed_results)
    
    logger.info(f"Test results saved to {csv_file}")
    
    # Create visualizations
    try:
        df = pd.DataFrame(processed_results)
        
        # 1. Attack types and their results
        plt.figure(figsize=(12, 6))
        sns.countplot(x="Attack Type", hue="Final Verdict", data=df)
        plt.title("Security Test Verdicts by Attack Type")
        plt.xlabel("Attack Type")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("attack_results.png")
        
        # 2. Response times for different attack types
        if "Response Time (ms)" in df.columns:
            plt.figure(figsize=(12, 6))
            sns.barplot(x="Attack Type", y="Response Time (ms)", data=df)
            plt.title("Response Times by Attack Type")
            plt.xlabel("Attack Type")
            plt.ylabel("Response Time (ms)")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig("response_times.png")
        
        logger.info("Visualizations generated successfully")
    except Exception as e:
        logger.error(f"Failed to generate visualizations: {e}")

def main():
    """Main entry point for the test system."""
    logger.info("Starting IoT Security Test System")
    
    # Run all tests
    results = run_comprehensive_tests()
    
    # Generate reports
    generate_reports(results)
    
    logger.info("Test execution completed")
    print(f"All tests completed. Results saved to iot_security_test_results.csv")

if __name__ == "__main__":
    main()