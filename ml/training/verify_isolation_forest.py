from pathlib import Path

import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
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


THRESHOLD = -0.10


print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

normal_train = train_df[
    train_df["target"] == 0
].copy()

X_normal = normal_train[FEATURE_COLUMNS]

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["target"]


print(f"Normal training samples: {len(X_normal)}")
print(f"Test samples:           {len(X_test)}")


print("\nBuilding preprocessing pipeline...")

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


print("\nFitting preprocessing on NORMAL training data...")

X_normal_transformed = preprocessor.fit_transform(
    X_normal
)

X_test_transformed = preprocessor.transform(
    X_test
)


print(
    f"Transformed normal shape: "
    f"{X_normal_transformed.shape}"
)

print(
    f"Transformed test shape:   "
    f"{X_test_transformed.shape}"
)


print("\nTraining Isolation Forest...")

model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)

model.fit(X_normal_transformed)

print("Training complete.")


print("\nCalculating anomaly scores...")

scores = model.decision_function(
    X_test_transformed
)

print("Anomaly scores calculated.")

print("\nScore statistics:")
print(f"Minimum: {scores.min():.6f}")
print(f"Maximum: {scores.max():.6f}")
print(f"Mean:    {scores.mean():.6f}")
print(f"Median:  {pd.Series(scores).median():.6f}")


print("\nApplying threshold...")

y_pred = (
    scores <= THRESHOLD
).astype(int)


print("\n")
print("=" * 80)
print("ISOLATION FOREST VERIFICATION")
print("=" * 80)

print(f"\nThreshold: {THRESHOLD}")

print(
    f"\nAccuracy: "
    f"{accuracy_score(y_test, y_pred):.4f}"
)

print(
    f"Attack Precision: "
    f"{precision_score(y_test, y_pred):.4f}"
)

print(
    f"Attack Recall: "
    f"{recall_score(y_test, y_pred):.4f}"
)

print(
    f"Attack F1: "
    f"{f1_score(y_test, y_pred):.4f}"
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["NORMAL", "ATTACK"],
    )
)
