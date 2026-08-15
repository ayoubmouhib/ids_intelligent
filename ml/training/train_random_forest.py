from pathlib import Path

import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    classification_report,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
TEST_PATH = Path("data/processed/nsl-kdd/test.csv")


FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]


CATEGORICAL_FEATURES = [
    "protocol_type",
    "service",
    "flag",
]


NUMERICAL_FEATURES = [
    column
    for column in FEATURE_COLUMNS
    if column not in CATEGORICAL_FEATURES
]


print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

X_train = train_df[FEATURE_COLUMNS]
y_train = train_df["target"]

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["target"]


print(f"Training shape: {X_train.shape}")
print(f"Test shape:     {X_test.shape}")


preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore",
                sparse_output=True,
            ),
            CATEGORICAL_FEATURES,
        ),
        (
            "numerical",
            "passthrough",
            NUMERICAL_FEATURES,
        ),
    ]
)


model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
)


pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("model", model),
    ]
)


print("Training Random Forest...")

pipeline.fit(X_train, y_train)

print("Training complete.")


y_proba = pipeline.predict_proba(X_test)[:, 1]

thresholds = [0.5, 0.4, 0.3, 0.2]

print("\nThreshold analysis")
print("=" * 60)

for threshold in thresholds:
    y_pred = (y_proba >= threshold).astype(int)

    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"\nThreshold: {threshold:.2f}")
    print(f"Attack Precision: {precision:.4f}")
    print(f"Attack Recall:    {recall:.4f}")
    print(f"Attack F1:        {f1:.4f}")

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))


print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)


print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["NORMAL", "ATTACK"],
    )
)