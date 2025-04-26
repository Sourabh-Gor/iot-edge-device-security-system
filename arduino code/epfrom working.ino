#include <Wire.h>

#define EEPROM_I2C_ADDRESS 0x50  // 24C256 I2C Address

void setup() {
    Serial.begin(115200);
    Wire.begin(14, 13);  // SDA = GPIO 14, SCL = GPIO 13
    delay(10000);
    Serial.println("\n📀 Testing 24C256 EEPROM...");

    int testAddress = 0x000A;
    byte testData = 0x42;

    Serial.print("🔄 Writing 0x");
    Serial.print(testData, HEX);
    Serial.print(" to address 0x");
    Serial.println(testAddress, HEX);
    
    writeEEPROM(testAddress, testData);
    delay(10);

    Serial.println("🔄 Reading from EEPROM...");
    byte readData = readEEPROM(testAddress);

    Serial.print("📖 Read Data: 0x");
    Serial.println(readData, HEX);

    if (readData == testData) {
        Serial.println("✅ EEPROM Test Passed!");
    } else {
        Serial.println("❌ EEPROM Test Failed!");
    }
}

void writeEEPROM(int address, byte data) {
    Wire.beginTransmission(EEPROM_I2C_ADDRESS);
    Wire.write((address >> 8) & 0xFF);  
    Wire.write(address & 0xFF);
    Wire.write(data);
    Wire.endTransmission();
    delay(5);
}

byte readEEPROM(int address) {
    Wire.beginTransmission(EEPROM_I2C_ADDRESS);
    Wire.write((address >> 8) & 0xFF);
    Wire.write(address & 0xFF);
    Wire.endTransmission();
    Wire.requestFrom(EEPROM_I2C_ADDRESS, 1);
    return Wire.available() ? Wire.read() : 0xFF;
}

void loop() {}
