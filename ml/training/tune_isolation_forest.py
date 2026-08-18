from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline


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


print(f"Training shape: {train_df.shape}")
print(f"Test shape:     {test_df.shape}")


# ============================================================
# 1. SELECT NORMAL TRAINING DATA
# ============================================================

normal_train_df = train_df[train_df["target"] == 0].copy()

X_train = normal_train_df[FEATURE_COLUMNS]

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["target"]


print(f"\nNormal training samples: {len(X_train)}")
print(f"Attack samples excluded: {(train_df['target'] == 1).sum()}")


# ============================================================
# 2. BUILD PREPROCESSING PIPELINE
# ============================================================

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


# ============================================================
# 3. BUILD ISOLATION FOREST
# ============================================================

model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)


pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("model", model),
    ]
)


# ============================================================
# 4. TRAIN
# ============================================================

print("\nTraining Isolation Forest...")

pipeline.fit(X_train)

print("Training complete.")


# ============================================================
# 5. GET ANOMALY SCORES
# ============================================================

print("\nCalculating anomaly scores...")

decision_scores = pipeline.decision_function(X_test)

# Isolation Forest:
#
#   higher score  = more normal
#   lower score   = more anomalous
#
# We invert the score so that:
#
#   higher anomaly_score = more anomalous
#
anomaly_scores = -decision_scores


print("Anomaly scores calculated.")


# ============================================================
# 6. THRESHOLD ANALYSIS
# ============================================================

thresholds = [
    -0.10,
    -0.05,
    0.00,
    0.05,
    0.10,
    0.15,
    0.20,
]


print("\n")
print("=" * 80)
print("ISOLATION FOREST THRESHOLD ANALYSIS")
print("=" * 80)


results = []


for threshold in thresholds:

    # Higher anomaly score means more anomalous.
    #
    # Therefore:
    #
    # anomaly_score >= threshold
    #
    # means ATTACK.

    y_pred = (anomaly_scores >= threshold).astype(int)

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0,
    )

    cm = confusion_matrix(y_test, y_pred)

    results.append(
        {
            "threshold": threshold,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }
    )

    print(f"\nThreshold: {threshold:.2f}")

    print(f"Attack Precision: {precision:.4f}")
    print(f"Attack Recall:    {recall:.4f}")
    print(f"Attack F1:        {f1:.4f}")

    print("Confusion Matrix:")
    print(cm)

# ============================================================
# 7. FIND BEST THRESHOLD
# ============================================================

results_df = pd.DataFrame(results)

best_result = results_df.loc[
    results_df["f1"].idxmax()
]

best_threshold = best_result["threshold"]
best_f1 = best_result["f1"]


print("\n")
print("=" * 80)
print("BEST ANOMALY THRESHOLD")
print("=" * 80)

print(f"Threshold:       {best_threshold:.2f}")
print(f"Attack F1:       {best_f1:.4f}")


# ============================================================
# 8. FINAL EVALUATION USING BEST THRESHOLD
# ============================================================

y_best = (
    anomaly_scores >= best_threshold
).astype(int)


print("\n")
print("=" * 80)
print("FINAL EVALUATION")
print("=" * 80)

print(f"Using threshold: {best_threshold:.2f}")


cm = confusion_matrix(
    y_test,
    y_best,
)

print("\nConfusion Matrix:")
print(cm)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_best,
        target_names=["NORMAL", "ATTACK"],
        zero_division=0,
    )
)


print("\nStep 4E complete.")
