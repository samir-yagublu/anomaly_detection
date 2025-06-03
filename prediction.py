import pandas as pd
import joblib

# 🔹 Step 1: Load your CSV file
df = pd.read_csv('finished_flow.csv')

# 🔹 Step 2: Define features and label
features = [
    'spkts', 'sbytes', 'dttl', 'dload', 'swin', 'synack', 'dmean',
    'ct_dst_sport_ltm', 'ct_srv_dst', 'proto_others', 'proto_arp', 'proto_udp',
    'service_dns', 'service_-', 'service_ftp', 'service_http', 'service_radius', 'service_smtp'
]
target_col = 'label'

# 🔹 Step 3: Split data into features and labels
X = df[features]
#X = X.dropna()
y = df[target_col]

# 🔹 Step 5: Load the trained model
model = joblib.load('random_forest_model.pkl')

# 🔹 Step 6: Predict
predictions = model.predict(X)

# 🔹 Step 7: Save or view predictions
df['predicted_label'] = predictions

# 🔹 Add this line to display all rows (or a specific number, e.g., 100)
# pd.set_option('display.max_rows', 100) # Uncomment and set a number if you want a specific limit
pd.set_option('display.max_rows', None) # Uncomment this line to display all rows


print(df[['label', 'predicted_label']]) # This will now print all rows
