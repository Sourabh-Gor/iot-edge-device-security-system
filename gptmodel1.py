import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    r2_score, mean_absolute_error, mean_squared_error, 
    explained_variance_score, max_error
)
import joblib

# ---------------------------
# Step 1: Generate Synthetic Data
# ---------------------------
np.random.seed(42)
n_samples = 2000  # increased dataset size

data = {
    'temp': np.random.normal(loc=35, scale=5, size=n_samples),      # °C
    'humidity': np.random.uniform(30, 90, size=n_samples),          # %
    'cpu': np.random.uniform(0, 100, size=n_samples),               # %
    'memory': np.random.uniform(0, 100, size=n_samples),            # %
    'signal': np.random.uniform(-100, -30, size=n_samples)          # dBm
}

df = pd.DataFrame(data)

# ---------------------------
# Step 2: Generate Health Score (target)
# ---------------------------
df['health'] = (
    0.25 * (100 - df['cpu']) +
    0.25 * (100 - df['memory']) +
    0.25 * ((df['signal'] + 100) / 70 * 100) +  # Normalize signal strength
    0.15 * (100 - abs(df['temp'] - 35)) +       # Ideal temp ~35°C
    0.10 * (100 - abs(df['humidity'] - 60))     # Ideal humidity ~60%
)

df['health'] = df['health'].clip(0, 100)

# ---------------------------
# Step 3: Model Training
# ---------------------------
X = df.drop(columns=['health'])
y = df['health']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestRegressor(
    n_estimators=10,
    max_depth=5,
    min_samples_split=5,
    random_state=42
)
model.fit(X_train, y_train)

# ---------------------------
# Step 4: Evaluation
# ---------------------------
y_pred = model.predict(X_test)

print("---- Model Performance Metrics ----")
print(f"R² Score: {r2_score(y_test, y_pred):.4f}")
print(f"Mean Absolute Error: {mean_absolute_error(y_test, y_pred):.4f}")
print(f"Mean Squared Error: {mean_squared_error(y_test, y_pred):.4f}")
print(f"Root Mean Squared Error: {np.sqrt(mean_squared_error(y_test, y_pred)):.4f}")
print(f"Explained Variance Score: {explained_variance_score(y_test, y_pred):.4f}")
print(f"Max Error: {max_error(y_test, y_pred):.4f}")

# ---------------------------
# Step 5: Model Parameters
# ---------------------------
print("\n---- Model Parameters ----")
print(model.get_params())

# ---------------------------
# Step 6: Save the model
# ---------------------------
joblib.dump(model, "iot_health_model_small.pkl")
print("\nModel saved as 'iot_health_model_small.pkl'")
