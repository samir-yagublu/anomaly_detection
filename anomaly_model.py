import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import xgboost as xgb
import plotly.express as px
import plotly.graph_objects as go
from sklearn.decomposition import PCA
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.impute import SimpleImputer
import joblib

# Just use the file names directly if they are in the same folder
file_path = 'UNSW_NB15_training-set.csv'
file_path2 = 'UNSW_NB15_testing-set.csv'

train_set = pd.read_csv(file_path)
test_set = pd.read_csv(file_path2)

train_set['proto'] = train_set['proto'].apply(lambda x: x if x in ['tcp', 'udp', 'arp'] else 'others')
test_set['proto'] = test_set['proto'].apply(lambda x: x if x in ['tcp', 'udp', 'arp'] else 'others')
#train_set['proto'].value_counts()
test_set['proto'].value_counts()

categorical_cols =['id','proto', 'service', 'state', 'attack_cat', 'label','is_sm_ips_ports', 'is_ftp_login']

test_set = test_set[
    ~(
        test_set['state'].isin(['URN', 'ECO', 'no', 'PAR'])
    )
]






from sklearn.preprocessing import StandardScaler

def scale_data_keep_categorical(train_df, test_df, target_col='label', categorical_cols=[]):
    # Save labels
    train_labels = train_df[target_col].astype(int)
    test_labels = test_df[target_col].astype(int)

    # Drop label and categorical columns to scale only numerical ones
    train_numerical = train_df.drop(categorical_cols , axis=1)
    test_numerical = test_df.drop(categorical_cols , axis=1)

    # Scale numerical featuresS
    scaler = StandardScaler()
    train_scaled = scaler.fit_transform(train_numerical)
    test_scaled = scaler.transform(test_numerical)

    # Convert scaled data back to DataFrames
    train_scaled_df = pd.DataFrame(train_scaled, columns=train_numerical.columns)
    test_scaled_df = pd.DataFrame(test_scaled, columns=test_numerical.columns)

    # Reattach categorical columns and label
    train_final = pd.concat([train_scaled_df, train_df[categorical_cols].reset_index(drop=True)], axis=1)
    test_final = pd.concat([test_scaled_df, test_df[categorical_cols].reset_index(drop=True)], axis=1)

    train_final[target_col] = train_labels.values
    test_final[target_col] = test_labels.values

    return train_final, test_final,scaler



train_scaled, test_scaled,my_scaler = scale_data_keep_categorical(train_set, test_set, target_col='label', categorical_cols=categorical_cols)
joblib.dump(my_scaler, 'scaler.pkl')

# Choose the categorical columns to encode
categorical_cols = ['proto', 'service', 'state']  #encoding only needed columns (label for output and attack_cat is not needed)

# Concatenate train and test to ensure consistent encoding
combined = pd.concat([train_scaled, test_scaled], keys=['train', 'test'])

# One-hot encode
combined_encoded = pd.get_dummies(combined, columns=categorical_cols)

# Split back into train and test
train_set_encoded = combined_encoded.xs('train')
test_set_encoded = combined_encoded.xs('test')




X = train_set_encoded.drop(columns=['id', 'label', 'attack_cat', 'proto_tcp', 'dwin', 'dloss', 'dbytes', 'ct_ftp_cmd', 'ct_srv_src', 'ct_dst_src_ltm', 'sloss', 'ct_dst_ltm', 'ct_src_ltm', 'is_sm_ips_ports', 'tcprtt'])
  # Drop the target column from features
y = train_set_encoded['label']  # Target variable
X_test_selected = test_set_encoded.drop(columns=['id','label', 'attack_cat']) #Test dataset
y_test = test_set_encoded['label']  # Test dataset



features = ['spkts', 'sbytes', 'dttl', 'dload', 'swin', 'synack' , 'dmean',
            'ct_dst_sport_ltm' , 'ct_srv_dst', 'proto_others','proto_arp', 'proto_udp','service_dns',
       'service_-', 'service_ftp', 'service_http', 'service_radius','service_smtp']


X_train_selected = X[features]
X_test_selected = X_test_selected[features]

XX_train, XX_test, yy_train, yy_test = train_test_split(X_train_selected, y, test_size=0.15, random_state=42)



from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns

# Step 2: Train Random Forest model
rf_model = RandomForestClassifier(n_estimators=105, random_state=42,class_weight={0: 1.0, 1: 3}) #3 best now
rf_model.fit(XX_train, yy_train)  # Train on the training data

# Step 3: Predict on test data (the unseen test set)
y_test_pred = rf_model.predict(XX_test)

# Step 4: Calculate accuracy
accuracy = accuracy_score(yy_test, y_test_pred)
print(f"Accuracy on the Test Set: {accuracy:.4f}")


# Confusion matrix for the test data
cm_test = confusion_matrix(yy_test, y_test_pred)
plt.figure(figsize=(6, 4))
sns.heatmap(cm_test, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix - Train Data')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()

# Classification report for the test data
print("Classification Report - Train Data:")
print(classification_report(yy_test, y_test_pred))


joblib.dump(rf_model, 'random_forest_model.pkl')



y_test_pred = rf_model.predict(X_test_selected)

# Step 3: Confusion matrix for the test dataset
cm_test = confusion_matrix(y_test, y_test_pred)
plt.figure(figsize=(6, 4))
sns.heatmap(cm_test, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix - Test Data')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()

# Step 4: Classification report for the test dataset
print("Classification Report - Test Data:")
print(classification_report(y_test, y_test_pred))
# Step 5: Accuracy on the test dataset
test_accuracy = accuracy_score(y_test, y_test_pred)
print(f"Accuracy on the Test Dataset: {test_accuracy:.4f}")
