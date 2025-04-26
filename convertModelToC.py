from joblib import load
from micromlgen import port

# Load your trained model
model = load("iot_health_model_small.pkl")

# Convert to C++ header
with open("iot_health_model3.h", "w") as f:
    f.write(port(model, class_name="IoTHealthModel"))
