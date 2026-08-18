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


# =========================================================
# LOAD DATA
# =========================================================

print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

print(f"Training shape: {train_df.shape}")
print(f"Test shape:     {test_df.shape}")


# =========================================================
# NORMAL-ONLY TRAINING
# =========================================================

normal_df = train_df[train_df["target"] == 0].copy()

X_normal = normal_df[FEATURE_COLUMNS]

print(f"\nNormal training samples: {len(X_normal)}")


# =========================================================
# TEST DATA
# =========================================================

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["target"]


# =========================================================
# PREPROCESSING
# =========================================================

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


# =========================================================
# ISOLATION FOREST
# =========================================================

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


# =========================================================
# TRAIN
# =========================================================

print("\nTraining Isolation Forest...")

pipeline.fit(X_normal)

print("Training complete.")


# =========================================================
# PREDICT
# =========================================================

print("\nPredicting test data...")

raw_predictions = pipeline.predict(X_test)

y_pred = (raw_predictions == -1).astype(int)


# =========================================================
# OVERALL EVALUATION
# =========================================================

print("\n")
print("=" * 80)
print("OVERALL ANOMALY DETECTION RESULTS")
print("=" * 80)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print(f"\nAccuracy:          {accuracy:.4f}")
print(f"Attack Precision:  {precision:.4f}")
print(f"Attack Recall:     {recall:.4f}")
print(f"Attack F1:         {f1:.4f}")

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


# =========================================================
# ATTACK TYPE ANALYSIS
# =========================================================

print("\n")
print("=" * 80)
print("ATTACK TYPE ANOMALY ANALYSIS")
print("=" * 80)

attack_results = test_df[test_df["target"] == 1].copy()

attack_results["prediction"] = y_pred[test_df["target"].values == 1]

rows = []

for attack_type, group in attack_results.groupby("label"):
    total = len(group)

    detected = int((group["prediction"] == 1).sum())

    missed = total - detected

    attack_recall = detected / total if total > 0 else 0.0

    rows.append(
        {
            "attack_type": attack_type,
            "total": total,
            "detected": detected,
            "missed": missed,
            "recall": attack_recall,
        }
    )


attack_report = pd.DataFrame(rows)

attack_report = attack_report.sort_values(
    by="missed",
    ascending=False,
)


print("\nAttack detection by type")
print("-" * 80)

print(
    attack_report.to_string(
        index=False,
        formatters={
            "recall": "{:.4f}".format,
        },
    )
)


# =========================================================
# SHARED VS TEST-ONLY
# =========================================================

training_attack_types = set(
    train_df.loc[
        train_df["target"] == 1,
        "label",
    ].unique()
)

test_attack_types = set(
    test_df.loc[
        test_df["target"] == 1,
        "label",
    ].unique()
)

shared_attack_types = (
    training_attack_types
    & test_attack_types
)

test_only_attack_types = (
    test_attack_types
    - training_attack_types
)


print("\n")
print("=" * 80)
print("SHARED VS TEST-ONLY ATTACKS")
print("=" * 80)

print(
    f"\nShared attack types:   {len(shared_attack_types)}"
)

print(
    f"Test-only attack types: {len(test_only_attack_types)}"
)


# =========================================================
# SHARED ATTACKS
# =========================================================

shared_mask = attack_results["label"].isin(
    shared_attack_types
)

shared_predictions = attack_results.loc[
    shared_mask,
    "prediction",
]

shared_total = len(shared_predictions)

shared_detected = int(
    (shared_predictions == 1).sum()
)

shared_recall = (
    shared_detected / shared_total
    if shared_total > 0
    else 0.0
)


print("\nSHARED ATTACKS")
print("-" * 80)

print(f"Samples:         {shared_total}")
print(f"Detected:        {shared_detected}")
print(f"Missed:          {shared_total - shared_detected}")
print(f"Attack recall:   {shared_recall:.4f}")


# =========================================================
# TEST-ONLY ATTACKS
# =========================================================

test_only_mask = attack_results["label"].isin(
    test_only_attack_types
)

test_only_predictions = attack_results.loc[
    test_only_mask,
    "prediction",
]

test_only_total = len(test_only_predictions)

test_only_detected = int(
    (test_only_predictions == 1).sum()
)

test_only_recall = (
    test_only_detected / test_only_total
    if test_only_total > 0
    else 0.0
)


print("\nTEST-ONLY ATTACKS")
print("-" * 80)

print(f"Samples:         {test_only_total}")
print(f"Detected:        {test_only_detected}")
print(f"Missed:          {test_only_total - test_only_detected}")
print(f"Attack recall:   {test_only_recall:.4f}")


print("\nStep 4D complete.")