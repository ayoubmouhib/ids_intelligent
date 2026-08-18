from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
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
OUTPUT_DIR = Path("data/analysis")


RF_THRESHOLD = 0.40
IF_THRESHOLD = -0.10


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


# ============================================================
# 1. LOAD DATA
# ============================================================

print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

print(f"Training rows: {len(train_df)}")
print(f"Test rows:     {len(test_df)}")


X_train = train_df[FEATURE_COLUMNS]
y_train = train_df["target"]

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["target"]


# ============================================================
# 2. RANDOM FOREST
# ============================================================

print("\n")
print("=" * 80)
print("TRAINING RANDOM FOREST")
print("=" * 80)

rf_preprocessor = ColumnTransformer(
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


rf_model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
)


rf_pipeline = Pipeline(
    steps=[
        ("preprocessor", rf_preprocessor),
        ("model", rf_model),
    ]
)


rf_pipeline.fit(X_train, y_train)

rf_probability = rf_pipeline.predict_proba(X_test)[:, 1]

rf_pred = (
    rf_probability >= RF_THRESHOLD
).astype(int)


# ============================================================
# 3. ISOLATION FOREST
# ============================================================

print("\n")
print("=" * 80)
print("TRAINING ISOLATION FOREST")
print("=" * 80)

normal_train_df = train_df[
    train_df["target"] == 0
].copy()

X_normal = normal_train_df[FEATURE_COLUMNS]

print(f"Normal training samples: {len(X_normal)}")


if_preprocessor = ColumnTransformer(
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


if_model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)


if_pipeline = Pipeline(
    steps=[
        ("preprocessor", if_preprocessor),
        ("model", if_model),
    ]
)


if_pipeline.fit(X_normal)

if_decision_score = if_pipeline.decision_function(X_test)

if_pred = (
    if_decision_score <= IF_THRESHOLD
).astype(int)


# ============================================================
# 4. HYBRID DECISION
# ============================================================

print("\n")
print("=" * 80)
print("BUILDING HYBRID DECISIONS")
print("=" * 80)

hybrid_decision = np.full(
    len(test_df),
    "NORMAL",
    dtype=object,
)

# RF says attack → ATTACK
hybrid_decision[
    rf_pred == 1
] = "ATTACK"


# RF says normal but IF detects anomaly
suspicious_mask = (
    (rf_pred == 0)
    & (if_pred == 1)
)

hybrid_decision[
    suspicious_mask
] = "SUSPICIOUS"


# Binary evaluation:
#
# ATTACK and SUSPICIOUS are both
# considered positive detections.
hybrid_binary = (
    hybrid_decision != "NORMAL"
).astype(int)


# ============================================================
# 5. OVERALL MODEL COMPARISON
# ============================================================

print("\n")
print("=" * 80)
print("OVERALL MODEL COMPARISON")
print("=" * 80)


models = {
    "Random Forest": rf_pred,
    "Isolation Forest": if_pred,
    "Hybrid IDS": hybrid_binary,
}


comparison = []


for name, predictions in models.items():

    comparison.append(
        {
            "model": name,
            "accuracy": accuracy_score(
                y_test,
                predictions,
            ),
            "precision": precision_score(
                y_test,
                predictions,
                zero_division=0,
            ),
            "recall": recall_score(
                y_test,
                predictions,
                zero_division=0,
            ),
            "f1": f1_score(
                y_test,
                predictions,
                zero_division=0,
            ),
        }
    )


comparison_df = pd.DataFrame(comparison)

print(comparison_df.to_string(index=False))


# ============================================================
# 6. HYBRID CONFUSION MATRIX
# ============================================================

print("\n")
print("=" * 80)
print("HYBRID CONFUSION MATRIX")
print("=" * 80)

hybrid_cm = confusion_matrix(
    y_test,
    hybrid_binary,
)

print(hybrid_cm)


# ============================================================
# 7. HYBRID DECISION DISTRIBUTION
# ============================================================

print("\n")
print("=" * 80)
print("HYBRID DECISION DISTRIBUTION")
print("=" * 80)

decision_counts = pd.Series(
    hybrid_decision
).value_counts()

print(decision_counts)


# ============================================================
# 8. ERROR ANALYSIS
# ============================================================

print("\n")
print("=" * 80)
print("HYBRID ERROR ANALYSIS")
print("=" * 80)


false_positive_mask = (
    (y_test == 0)
    & (hybrid_binary == 1)
)

false_negative_mask = (
    (y_test == 1)
    & (hybrid_binary == 0)
)

true_positive_mask = (
    (y_test == 1)
    & (hybrid_binary == 1)
)

true_negative_mask = (
    (y_test == 0)
    & (hybrid_binary == 0)
)


print(
    f"True negatives:  {true_negative_mask.sum()}"
)

print(
    f"False positives: {false_positive_mask.sum()}"
)

print(
    f"True positives:  {true_positive_mask.sum()}"
)

print(
    f"False negatives: {false_negative_mask.sum()}"
)


# ============================================================
# 9. ATTACK TYPE ANALYSIS
# ============================================================

print("\n")
print("=" * 80)
print("HYBRID ATTACK TYPE ANALYSIS")
print("=" * 80)


attack_rows = test_df[
    test_df["target"] == 1
].copy()


attack_indices = attack_rows.index


attack_analysis = []


for attack_type, group in attack_rows.groupby(
    "label"
):

    indices = group.index

    total = len(indices)

    detected = hybrid_binary[indices].sum()

    missed = total - detected

    recall = (
        detected / total
        if total > 0
        else 0.0
    )

    rf_detected = rf_pred[indices].sum()

    if_detected = if_pred[indices].sum()

    suspicious = (
        hybrid_decision[indices]
        == "SUSPICIOUS"
    ).sum()

    attack_analysis.append(
        {
            "attack_type": attack_type,
            "total": total,
            "rf_detected": rf_detected,
            "rf_recall": rf_detected / total,
            "if_detected": if_detected,
            "if_recall": if_detected / total,
            "hybrid_detected": detected,
            "hybrid_missed": missed,
            "hybrid_recall": recall,
            "suspicious": suspicious,
        }
    )


attack_df = pd.DataFrame(
    attack_analysis
).sort_values(
    "hybrid_recall"
)


print(
    attack_df.to_string(index=False)
)


# ============================================================
# 10. SHARED VS TEST-ONLY
# ============================================================

print("\n")
print("=" * 80)
print("SHARED VS TEST-ONLY ATTACK ANALYSIS")
print("=" * 80)


train_attack_types = set(
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


shared_types = (
    train_attack_types
    & test_attack_types
)

test_only_types = (
    test_attack_types
    - train_attack_types
)


group_results = []


for group_name, attack_types in [
    ("SHARED", shared_types),
    ("TEST_ONLY", test_only_types),
]:

    mask = (
        (test_df["target"] == 1)
        & test_df["label"].isin(attack_types)
    )

    indices = test_df.index[mask]

    total = len(indices)

    rf_detected = rf_pred[indices].sum()
    if_detected = if_pred[indices].sum()
    hybrid_detected = hybrid_binary[indices].sum()

    rf_recall = (
        rf_detected / total
        if total
        else 0
    )

    if_recall = (
        if_detected / total
        if total
        else 0
    )

    hybrid_recall = (
        hybrid_detected / total
        if total
        else 0
    )

    group_results.append(
        {
            "group": group_name,
            "samples": total,
            "rf_recall": rf_recall,
            "if_recall": if_recall,
            "hybrid_recall": hybrid_recall,
            "rf_f1": f1_score(
                y_test[indices],
                rf_pred[indices],
                zero_division=0,
            ),
            "if_f1": f1_score(
                y_test[indices],
                if_pred[indices],
                zero_division=0,
            ),
            "hybrid_f1": f1_score(
                y_test[indices],
                hybrid_binary[indices],
                zero_division=0,
            ),
        }
    )


group_df = pd.DataFrame(
    group_results
)

print(
    group_df.to_string(index=False)
)


# ============================================================
# 11. HARDEST ATTACKS
# ============================================================

print("\n")
print("=" * 80)
print("HARDEST ATTACK TYPES")
print("=" * 80)


hardest = (
    attack_df[
        attack_df["total"] >= 10
    ]
    .sort_values(
        "hybrid_recall"
    )
    .head(10)
)


print(
    hardest[
        [
            "attack_type",
            "total",
            "hybrid_detected",
            "hybrid_missed",
            "hybrid_recall",
        ]
    ].to_string(index=False)
)


# ============================================================
# 12. BEST DETECTED ATTACKS
# ============================================================

print("\n")
print("=" * 80)
print("BEST DETECTED ATTACK TYPES")
print("=" * 80)


best = (
    attack_df[
        attack_df["total"] >= 10
    ]
    .sort_values(
        "hybrid_recall",
        ascending=False,
    )
    .head(10)
)


print(
    best[
        [
            "attack_type",
            "total",
            "hybrid_detected",
            "hybrid_missed",
            "hybrid_recall",
        ]
    ].to_string(index=False)
)


# ============================================================
# 13. FINAL INTERPRETATION
# ============================================================

hybrid_row = comparison_df[
    comparison_df["model"]
    == "Hybrid IDS"
].iloc[0]


rf_row = comparison_df[
    comparison_df["model"]
    == "Random Forest"
].iloc[0]


print("\n")
print("=" * 80)
print("FINAL HYBRID IDS INTERPRETATION")
print("=" * 80)


print(
    f"""
Random Forest:
  Accuracy: {rf_row["accuracy"]:.4f}
  Attack precision: {rf_row["precision"]:.4f}
  Attack recall: {rf_row["recall"]:.4f}
  Attack F1: {rf_row["f1"]:.4f}

Hybrid IDS:
  Accuracy: {hybrid_row["accuracy"]:.4f}
  Attack precision: {hybrid_row["precision"]:.4f}
  Attack recall: {hybrid_row["recall"]:.4f}
  Attack F1: {hybrid_row["f1"]:.4f}

Configuration:
  RF threshold: {RF_THRESHOLD:.2f}
  IF threshold: {IF_THRESHOLD:.2f}

The Random Forest provides the primary supervised
attack classification.

The Isolation Forest provides a complementary
anomaly signal for traffic that differs from
normal training behavior.

RF ATTACK + IF anything:
  -> ATTACK

RF NORMAL + IF ANOMALY:
  -> SUSPICIOUS

RF NORMAL + IF NORMAL:
  -> NORMAL
"""
)


# ============================================================
# 14. SAVE RESULTS
# ============================================================

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


comparison_df.to_csv(
    OUTPUT_DIR
    / "final_model_comparison.csv",
    index=False,
)


attack_df.to_csv(
    OUTPUT_DIR
    / "final_hybrid_attack_analysis.csv",
    index=False,
)


group_df.to_csv(
    OUTPUT_DIR
    / "final_hybrid_group_comparison.csv",
    index=False,
)


# Save row-level errors
error_df = test_df[
    false_positive_mask
    | false_negative_mask
].copy()

error_df["hybrid_prediction"] = (
    hybrid_binary[
        error_df.index
    ]
)

error_df["hybrid_decision"] = (
    hybrid_decision[
        error_df.index
    ]
)

error_df["rf_prediction"] = (
    rf_pred[
        error_df.index
    ]
)

error_df["if_prediction"] = (
    if_pred[
        error_df.index
    ]
)

error_df.to_csv(
    OUTPUT_DIR
    / "final_hybrid_errors.csv",
    index=False,
)


print("\n")
print("=" * 80)
print("STEP 4I COMPLETE")
print("=" * 80)

print(
    "Saved:"
)

print(
    "  data/analysis/final_model_comparison.csv"
)

print(
    "  data/analysis/final_hybrid_attack_analysis.csv"
)

print(
    "  data/analysis/final_hybrid_group_comparison.csv"
)

print(
    "  data/analysis/final_hybrid_errors.csv"
)
