#include <Adafruit_Sensor.h>
#include <DHT.h>
#include <DHT_U.h>

#define DHTPIN 4      // Pin for DHT22 (Make sure it's not conflicting)
#define DHTTYPE DHT22 // Sensor type

DHT dht(DHTPIN, DHTTYPE);

void setup() {
    Serial.begin(115200);
    while (!Serial);
    delay(10000);
    Serial.println("\n🚀 Starting DHT22 Sensor Test...");

    dht.begin();
}

void loop() {
    Serial.println("🔄 Reading DHT22 sensor...");
    
    float temperature = dht.readTemperature(); // Celsius
    float humidity = dht.readHumidity();

    if (isnan(temperature) || isnan(humidity)) {
        Serial.println("❌ ERROR: Failed to read from DHT sensor!");
    } else {
        Serial.print("🌡️ Temperature: ");
        Serial.print(temperature);
        Serial.println("°C");

        Serial.print("💧 Humidity: ");
        Serial.print(humidity);
        Serial.println("%");
    }

    delay(2000);  // Wait 2 seconds before next reading
}
