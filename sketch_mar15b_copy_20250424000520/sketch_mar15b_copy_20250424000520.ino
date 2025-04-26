//esp32.ino
#include <WiFi.h>
#include <HTTPClient.h>
#include <base64.h>
#include <ArduinoJson.h>
#include "mbedtls/gcm.h"
#include <Arduino.h>
#include <SHA256.h>
#include "iot_health_model3.h"

// WiFi credentials
const char* ssid = "Sou-Megh-4G";
const char* password = "sourabh@7474";
const char* serverName = "http://192.168.29.128:5000";
// const char* ssid = "iPhone";
// const char* password = "superduper";
// const char* serverName = "http://172.20.10.5:5000"; // Flask server URL

// Secret key for MAC generation
const char* SECRET_KEY = "supersecurekey_here_is_32_byte_l";
const int SECRET_KEY_LENGTH = 32;

// Configuration
const unsigned long healthCheckInterval = 1000;                      // Check every 60 sec
const unsigned long PERSISTENT_DEGRADATION_TIMEOUT = 5 * 60 * 1000;  // 5 minutes
const float HEALTH_THRESHOLD = 80.0;                                 // Percentage below which we trigger re-registration

// State variables
unsigned long lastHealthCheck = 0;
unsigned long degradationDetectedTime = 0;
bool deviceHealthy = true;
bool registrationKeyTriggered = false;

// Function to setup monitoring
void setupHealthMonitoring() {
  lastHealthCheck = millis();
  deviceHealthy = true;
  registrationKeyTriggered = false;
  Serial.println("[HEALTH] Device health monitoring initialized");
}

// Read sensor/metrics — stub functions to replace with your real sensor reads
float readTemperature() {
  return 36.0;
}  // replace with actual reading
float readHumidity() {
  return 55.0;
}  // replace with actual reading
float estimateCpuUsage() {
  return 20.0;
}  // custom logic or mock
float estimateMemoryUsage() {
  uint32_t freeHeap = ESP.getFreeHeap();
  uint32_t totalHeap = ESP.getHeapSize();              // on PSRAM-enabled ESP32
  if (totalHeap == 0) totalHeap = 320000;              // fallback if unavailable
  return 100.0 * (1.0 - (float)freeHeap / totalHeap);  // % used
}
float readWiFiSignalStrength() {
  return WiFi.RSSI();
}  // in dBm

// Device degradation check using the ML model
bool isDeviceDegraded(float temperature, float humidity, float cpu, float memory, float signal) {
  float input[] = { temperature, humidity, cpu, memory, signal };
  Eloquent::ML::Port::RandomForestRegressor model;
  float predictedHealth = model.predict(input);

  Serial.println("[HEALTH] Predicted health: " + String(predictedHealth, 2) + "%");

  return predictedHealth < HEALTH_THRESHOLD;
}

// Monitor device health every interval
void monitorDeviceHealth(String deviceName, String pufKey, String pufHash) {
  Serial.print("[DEBUG] Monitoring Health with Last Health Check at: ");
  Serial.println(lastHealthCheck);

  if (millis() - lastHealthCheck >= healthCheckInterval) {
    lastHealthCheck = millis();

    float temperature = readTemperature();
    float humidity = readHumidity();
    float cpu = estimateCpuUsage();
    float memory = estimateMemoryUsage();
    float signal = readWiFiSignalStrength();

    Serial.println("[HEALTH] Current device parameters:");
    Serial.println("  Temperature: " + String(temperature) + "°C");
    Serial.println("  Humidity: " + String(humidity) + "%");
    Serial.println("  CPU Usage: " + String(cpu) + "%");
    Serial.println("  Memory Usage: " + String(memory) + "%");
    Serial.println("  WiFi Signal: " + String(signal) + " dBm");

    bool degraded = isDeviceDegraded(temperature, humidity, cpu, memory, signal);
    Serial.print("[DEBUG] Device Degraded: ");
    Serial.print(degraded);
    if (degraded) {
      checkAndRegisterKey(deviceName, pufKey, pufHash);
    }
  }
}


// Function prototypes
String hashPUF(String pufKey);
String generateMAC(String data);
String generateNonce();
String respondToChallenge(String challenge);


// Enhanced PUF Key extraction
String extractPUFKey() {
  Serial.println("[DEBUG] Starting PUF key extraction...");
  const int SRAM_SIZE = 32;  // Read 32 bytes of SRAM
  uint8_t sramData[SRAM_SIZE];
  uint8_t pufBits[8] = { 0 };  // 8-bit PUF key

  for (int sample = 0; sample < 3; sample++) {
    Serial.println("[DEBUG] Taking SRAM sample " + String(sample + 1));
    uint32_t* sram = (uint32_t*)malloc(SRAM_SIZE);
    for (int i = 0; i < SRAM_SIZE / 4; i++) {
      sram[i] = sram[i];  // Dummy read
    }

    for (int i = 0; i < SRAM_SIZE; i++) {
      sramData[i] = (uint8_t)(sram[i % (SRAM_SIZE / 4)] >> (i % 4 * 8));
    }
    free(sram);

    for (int bit = 0; bit < 8; bit++) {
      int bitSum = 0;
      for (int byte = 0; byte < SRAM_SIZE; byte++) {
        bitSum += (sramData[byte] >> bit) & 1;
      }
      if (bitSum > SRAM_SIZE / 2) {
        pufBits[bit] += 1;
      }
    }
    delay(10);  // Small delay between samples
  }

  uint8_t pufKey = 0;
  for (int bit = 0; bit < 8; bit++) {
    if (pufBits[bit] >= 2) {  // Majority of 3 samples
      pufKey |= (1 << bit);
    }
  }

  char hexKey[3];
  sprintf(hexKey, "%02X", pufKey);
  String pufKeyStr = String(hexKey);
  Serial.println("[DEBUG] Extracted PUF Key: " + pufKeyStr);
  return pufKeyStr;
}

// Chaotic map (logistic map)
float logisticMap(float r, float x, int iterations) {
  for (int i = 0; i < iterations; i++) {
    x = r * x * (1 - x);
  }
  return x;
}

// Encrypt data using chaotic map and PUF key
String chaoticEncrypt(String data, String pufKey) {
  Serial.println("[DEBUG] Starting encryption with data: " + data);
  Serial.println("[DEBUG] Using PUF Key: " + pufKey);
  uint8_t keyValue = (uint8_t)strtol(pufKey.c_str(), NULL, 16);  // PUF key as integer
  float r = 3.5;                                                 // Fixed R-value
  float x = 0.5;                                                 // Fixed initial condition
  String encrypted = "";

  Serial.printf("[DEBUG] Fixed R-value: %.1f\n", r);
  String encryptedHex = "";
  for (int i = 0; i < data.length(); i++) {
    x = logisticMap(r, x, 10);
    uint8_t chaoticByte = (uint8_t)(x * 255);
    // First XOR with chaotic byte, then XOR with PUF key
    uint8_t encryptedByte = (data[i] ^ chaoticByte) ^ keyValue;

    char hex[3];
    sprintf(hex, "%02X", encryptedByte);
    encryptedHex += hex;
    Serial.printf("[DEBUG] Byte %d: Input=%d, Chaotic=%d, PUF=%d, Encrypted=%d\n",
                  i, (uint8_t)data[i], chaoticByte, keyValue, encryptedByte);
  }

  Serial.println("[DEBUG] Encrypted data (hex): " + encryptedHex);
  return encryptedHex;
}

void setup() {
  Serial.begin(115200);
  delay(10000);
  Serial.println("[DEBUG] Starting setup...");
  randomSeed(analogRead(0));
  WiFi.begin(ssid, password);
  Serial.println("[DEBUG] Connecting to WiFi...");
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("[DEBUG] Still connecting to WiFi...");
  }
  setupHealthMonitoring();
  Serial.println("[DEBUG] Connected to WiFi with IP: " + WiFi.localIP().toString());
}

void checkAndRegisterKey(String deviceName, String pufKey, String pufHash) {
  HTTPClient http;

  // Generate nonce for the request
  String nonce = generateNonce();

  // Create MAC for the request
  String macData = deviceName + pufHash + nonce;
  String mac = generateMAC(macData);

  // Create JSON payload
  DynamicJsonDocument checkDoc(256);
  checkDoc["device_name"] = deviceName;
  checkDoc["puf_hash"] = pufHash;
  checkDoc["nonce"] = nonce;
  checkDoc["mac"] = mac;

  String checkPayload;
  serializeJson(checkDoc, checkPayload);

  // Send check request
  http.begin(String(serverName) + "/check_key");
  http.addHeader("Content-Type", "application/json");
  Serial.println("[DEBUG] Checking PUF key with payload: " + checkPayload);

  int httpCode = http.POST(checkPayload);
  String response = http.getString();
  http.end();

  Serial.println("[DEBUG] Check key response: " + response + " (HTTP Code: " + String(httpCode) + ")");

  if (httpCode == 404) {
    // Key not found, register it
    registerKey(deviceName, pufKey, pufHash);
  }
}

void registerKey(String deviceName, String pufKey, String pufHash) {
  HTTPClient http;

  // First get a challenge from the server
  DynamicJsonDocument challengeDoc(128);
  challengeDoc["device_name"] = deviceName;

  String challengePayload;
  serializeJson(challengeDoc, challengePayload);

  http.begin(String(serverName) + "/generate_challenge");
  http.addHeader("Content-Type", "application/json");
  int httpCode = http.POST(challengePayload);

  if (httpCode != 200) {
    Serial.println("[ERROR] Failed to get challenge: " + String(httpCode));
    http.end();
    return;
  }

  String challengeResponse = http.getString();
  http.end();

  // Parse the challenge
  DynamicJsonDocument doc(512);
  deserializeJson(doc, challengeResponse);
  String challenge = doc["challenge"];

  Serial.println("[DEBUG] Received challenge: " + challenge);

  // Respond to challenge (in this case, we'll just reverse the challenge)
  String challengeResp = respondToChallenge(challenge);

  // Generate nonce for the registration
  String nonce = generateNonce();

  String encryptedKey = encryptPUFKey(pufKey, nonce);

  // Create MAC for the registration
  String macData = deviceName + challengeResp + nonce + encryptedKey + pufHash;
  String mac = generateMAC(macData);

  // Create JSON payload for registration
  DynamicJsonDocument regDoc(512);
  regDoc["device_name"] = deviceName;
  regDoc["challenge_response"] = challengeResp;
  regDoc["nonce"] = nonce;
  regDoc["encrypted_key"] = encryptedKey;
  regDoc["puf_hash"] = pufHash;
  regDoc["mac"] = mac;

  String regPayload;
  serializeJson(regDoc, regPayload);

  http.begin(String(serverName) + "/register_key");
  http.addHeader("Content-Type", "application/json");
  Serial.println("[DEBUG] Registering key with payload: " + regPayload);

  httpCode = http.POST(regPayload);
  String response = http.getString();
  http.end();

  Serial.println("[DEBUG] Register key response: " + response + " (HTTP Code: " + String(httpCode) + ")");
}

void sendSensorData(String deviceName, String pufKey) {
  float temp = 10.5;
  float humidity = 20.5;
  String rfidTag = "Test Rfid";
  String sensorData = String(temp) + "," + String(humidity) + "," + rfidTag;
  Serial.println("[DEBUG] Sensor Data: " + sensorData);

  String encryptedData = chaoticEncrypt(sensorData, pufKey);
  String base64String = base64::encode((uint8_t*)encryptedData.c_str(), encryptedData.length());

  // Generate nonce
  String nonce = generateNonce();

  // Create MAC for the data
  String macData = deviceName + base64String + nonce;
  String mac = generateMAC(macData);

  HTTPClient http;
  String dataUrl = String(serverName) + "/receive_data";
  Serial.println("[DEBUG] Sending data to URL: " + dataUrl);
  http.begin(dataUrl);
  http.addHeader("Content-Type", "application/json");

  // Create JSON payload
  DynamicJsonDocument dataDoc(512);
  dataDoc["device_name"] = deviceName;
  dataDoc["data"] = base64String;
  dataDoc["nonce"] = nonce;
  dataDoc["mac"] = mac;

  String dataPayload;
  serializeJson(dataDoc, dataPayload);

  Serial.println("[DEBUG] Sending data payload: " + dataPayload);
  int httpCode = http.POST(dataPayload);

  if (httpCode > 0) {
    String response = http.getString();
    Serial.println("[DEBUG] Data sent successfully. Response: " + response + " (HTTP Code: " + String(httpCode) + ")");
  } else {
    Serial.println("[DEBUG] Failed to send data. HTTP Code: " + String(httpCode));
  }
  http.end();
}

void loop() {
  String pufKey = extractPUFKey();
  String pufHash = hashPUF(pufKey);
  // String deviceName = "ESP32_" + WiFi.macAddress();
  uint32_t chipId = (uint32_t)ESP.getEfuseMac();  // Returns 64-bit, take lower 32-bits
  String deviceName = "ESP32_" + String(chipId, HEX);
  Serial.println("[DEBUG] Monitoring Health Now: ");
  Serial.println(deviceName);

  monitorDeviceHealth(deviceName, pufKey, pufHash);
  if (WiFi.status() == WL_CONNECTED) {
    // Check if our key is registered
    checkAndRegisterKey(deviceName, pufKey, pufHash);

    // Send sensor data
    sendSensorData(deviceName, pufKey);
  } else {
    Serial.println("[DEBUG] WiFi not connected!");
  }
  Serial.println("[DEBUG] Loop completed. Waiting 15 seconds...");
  delay(15000);
}

String hashPUF(String pufKey) {
  byte shaResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);

  mbedtls_md_update(&ctx, (const unsigned char*)pufKey.c_str(), pufKey.length());
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);

  char hashStr[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hashStr + (i * 2), "%02x", shaResult[i]);
  }
  hashStr[64] = '\0';

  return String(hashStr);
}

// Generate MAC
String generateMAC(String data) {
  byte hmacResult[32];

  // Initialize HMAC context
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);  // 1 for HMAC
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)SECRET_KEY, strlen(SECRET_KEY));

  mbedtls_md_hmac_update(&ctx, (const unsigned char*)data.c_str(), data.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  char macStr[65];
  for (int i = 0; i < 32; i++) {
    sprintf(macStr + (i * 2), "%02x", hmacResult[i]);
  }
  macStr[64] = '\0';

  return String(macStr);
}

// Generate a random nonce
String generateNonce() {
  char nonce[13];
  for (int i = 0; i < 12; i++) {
    nonce[i] = random(0, 36) < 10 ? '0' + random(0, 10) : 'a' + random(0, 26);
  }
  nonce[12] = '\0';
  return String(nonce);
}

String respondToChallenge(String challenge) {
  // Convert challenge to bytes
  int challengeLength = challenge.length();
  uint8_t challengeBytes[challengeLength];
  for (int i = 0; i < challengeLength; i++) {
    challengeBytes[i] = (uint8_t)challenge.charAt(i);
  }

  // Create hash input: challenge + secret key
  uint8_t hashInput[challengeLength + SECRET_KEY_LENGTH];
  memcpy(hashInput, challengeBytes, challengeLength);
  memcpy(hashInput + challengeLength, (uint8_t*)SECRET_KEY, SECRET_KEY_LENGTH);

  // Generate one-time pad using SHA256
  SHA256 sha256;
  uint8_t hash[32];
  sha256.reset();
  sha256.update(hashInput, challengeLength + SECRET_KEY_LENGTH);
  sha256.finalize(hash, 32);

  // XOR challenge with one-time pad
  uint8_t responseBytes[challengeLength];
  for (int i = 0; i < challengeLength; i++) {
    responseBytes[i] = challengeBytes[i] ^ hash[i];
  }

  // Convert to hex string
  String response = "";
  for (int i = 0; i < challengeLength; i++) {
    char hex[3];
    sprintf(hex, "%02x", responseBytes[i]);
    response += hex;
  }

  // Return first 16 characters of the hex string
  return response.substring(0, 16);
}

String encryptPUFKey(String pufKey, String nonceS) {
  const uint8_t* nonce = (const uint8_t*)nonceS.c_str();
  // 2. Prepare input and output buffers
  const size_t input_len = pufKey.length();
  uint8_t ciphertext[input_len];
  uint8_t tag[16];

  // 3. Setup AES-GCM
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const uint8_t*)SECRET_KEY, 256);  // 256 bits = 32 bytes

  int ret = mbedtls_gcm_crypt_and_tag(
    &gcm, MBEDTLS_GCM_ENCRYPT,
    input_len,
    nonce, 12,
    nullptr, 0,  // additional data
    (const uint8_t*)pufKey.c_str(),
    ciphertext,
    16, tag);
  mbedtls_gcm_free(&gcm);

  if (ret != 0) {
    Serial.println("Encryption failed!");
    return "";
  }

  // 4. Concatenate ciphertext + tag
  uint8_t encrypted_with_tag[input_len + 16];
  memcpy(encrypted_with_tag, ciphertext, input_len);
  memcpy(encrypted_with_tag + input_len, tag, 16);

  // 5. Base64 encode both
  String nonce_b64 = base64::encode(nonce, 12);
  String encrypted_b64 = base64::encode(encrypted_with_tag, input_len + 16);

  // 6. Format as nonce_b64:encrypted_b64
  return nonce_b64 + ":" + encrypted_b64;
}