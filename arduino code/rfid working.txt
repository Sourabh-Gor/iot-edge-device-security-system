#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 2   // ESP32 GPIO connected to RFID SS
#define RST_PIN 21 // ESP32 GPIO connected to RFID RST

MFRC522 rfid(SS_PIN, RST_PIN); // Create RFID instance

void setup() {
    Serial.begin(115200);
    while (!Serial);
    delay(10000);
    Serial.println("\n🚀 Starting RFID Test...");

    SPI.begin();
    rfid.PCD_Init();

    Serial.println("🔄 Checking RFID module...");
    byte version = rfid.PCD_ReadRegister(MFRC522::VersionReg);
    
    if (version == 0x00 || version == 0xFF) {
        Serial.println("❌ ERROR: RFID module not found! Check wiring.");
    } else {
        Serial.print("✅ RFID module detected! Version: 0x");
        Serial.println(version, HEX);
    }
}

void loop() {
    Serial.println("🔄 Scanning for RFID tags...");
  delay(1000);

  if (!rfid.PICC_IsNewCardPresent()) {
    Serial.println("⚠️ No new RFID card detected.");
    return;
  }

  Serial.println("✅ New RFID card detected!");

  if (!rfid.PICC_ReadCardSerial()) {
    Serial.println("❌ ERROR: Failed to read RFID card.");
    return;
  }

  Serial.print("🎫 Card UID: ");
  for (byte i = 0; i < rfid.uid.size; i++) {
    Serial.print(rfid.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(rfid.uid.uidByte[i], HEX);
  }
  Serial.println();

  Serial.print("🔢 Card UID (Decimal): ");
  for (byte i = 0; i < rfid.uid.size; i++) {
    Serial.print(rfid.uid.uidByte[i]);
    Serial.print(" ");
  }
  Serial.println();

  Serial.println("✅ Card read successfully!\n");

  rfid.PICC_HaltA(); // Halt communication with the RFID tag
}
