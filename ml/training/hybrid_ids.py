from pathlib import Path

import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier, IsolationForest
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


RF_THRESHOLD = 0.40
IF_THRESHOLD = -0.10


print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

X_train = train_df[FEATURE_COLUMNS]
y_train = train_df["target"]

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["target"]

print(f"Training shape: {train_df.shape}")
print(f"Test shape:     {test_df.shape}")


# ============================================================
# PREPROCESSING
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
# RANDOM FOREST
# ============================================================

print("\nTraining Random Forest...")

rf_model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
)

rf_pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("model", rf_model),
    ]
)

rf_pipeline.fit(X_train, y_train)

print("Random Forest training complete.")


# ============================================================
# ISOLATION FOREST
# ============================================================

print("\nPreparing normal traffic for Isolation Forest...")

normal_train = train_df[train_df["target"] == 0]

X_normal = normal_train[FEATURE_COLUMNS]

print(f"Normal training samples: {len(X_normal)}")

print("\nTraining Isolation Forest...")

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

X_normal_transformed = if_preprocessor.fit_transform(X_normal)

isolation_forest = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)

isolation_forest.fit(X_normal_transformed)

print("Isolation Forest training complete.")


# ============================================================
# PREDICTIONS
# ============================================================

print("\nPredicting test data...")

# Random Forest probabilities
rf_probability = rf_pipeline.predict_proba(X_test)[:, 1]

# Random Forest decision
rf_prediction = (
    rf_probability >= RF_THRESHOLD
).astype(int)


# Isolation Forest anomaly scores
X_test_transformed = if_preprocessor.transform(X_test)

if_score = isolation_forest.decision_function(
    X_test_transformed
)

# Lower score = more anomalous
if_prediction = (
    if_score <= IF_THRESHOLD
).astype(int)


# ============================================================
# HYBRID DECISION
# ============================================================

hybrid_prediction = []

for rf_pred, if_pred in zip(
    rf_prediction,
    if_prediction,
):

    if rf_pred == 1:
        # Random Forest says attack.
        hybrid_prediction.append(1)

    elif if_pred == 1:
        # RF says normal, but anomaly detector
        # considers the traffic unusual.
        hybrid_prediction.append(2)

    else:
        # Both models consider it normal.
        hybrid_prediction.append(0)


hybrid_prediction = pd.Series(
    hybrid_prediction,
    index=test_df.index,
)


# ============================================================
# HYBRID LABELS
# ============================================================

hybrid_labels = {
    0: "NORMAL",
    1: "ATTACK",
    2: "SUSPICIOUS",
}

hybrid_text = hybrid_prediction.map(hybrid_labels)


# ============================================================
# BASIC DISTRIBUTION
# ============================================================

print("\n")
print("=" * 80)
print("HYBRID IDS RESULTS")
print("=" * 80)

print("\nDecision distribution:")
print(hybrid_text.value_counts())


# ============================================================
# RANDOM FOREST RESULTS
# ============================================================

print("\n")
print("=" * 80)
print("RANDOM FOREST")
print("=" * 80)

print(
    f"Threshold:       {RF_THRESHOLD:.2f}"
)

print(
    f"Accuracy:        "
    f"{accuracy_score(y_test, rf_prediction):.4f}"
)

print(
    f"Attack Precision:"
    f" {precision_score(y_test, rf_prediction):.4f}"
)

print(
    f"Attack Recall:   "
    f"{recall_score(y_test, rf_prediction):.4f}"
)

print(
    f"Attack F1:       "
    f"{f1_score(y_test, rf_prediction):.4f}"
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, rf_prediction))


# ============================================================
# ISOLATION FOREST RESULTS
# ============================================================

print("\n")
print("=" * 80)
print("ISOLATION FOREST")
print("=" * 80)

print(
    f"Threshold:       {IF_THRESHOLD:.2f}"
)

print(
    f"Accuracy:        "
    f"{accuracy_score(y_test, if_prediction):.4f}"
)

print(
    f"Attack Precision:"
    f" {precision_score(y_test, if_prediction):.4f}"
)

print(
    f"Attack Recall:   "
    f"{recall_score(y_test, if_prediction):.4f}"
)

print(
    f"Attack F1:       "
    f"{f1_score(y_test, if_prediction):.4f}"
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, if_prediction))


# ============================================================
# HYBRID BINARY EVALUATION
# ============================================================
#
# For binary IDS evaluation:
#
# NORMAL     = 0
# ATTACK     = 1
# SUSPICIOUS = 1
#
# Therefore, suspicious traffic is treated as
# detected attack/anomaly.
# ============================================================

hybrid_binary = (
    hybrid_prediction > 0
).astype(int)


print("\n")
print("=" * 80)
print("HYBRID IDS - BINARY EVALUATION")
print("=" * 80)

print(
    f"RF threshold:    {RF_THRESHOLD:.2f}"
)

print(
    f"IF threshold:    {IF_THRESHOLD:.2f}"
)

print(
    f"Accuracy:        "
    f"{accuracy_score(y_test, hybrid_binary):.4f}"
)

print(
    f"Attack Precision:"
    f" {precision_score(y_test, hybrid_binary):.4f}"
)

print(
    f"Attack Recall:   "
    f"{recall_score(y_test, hybrid_binary):.4f}"
)

print(
    f"Attack F1:       "
    f"{f1_score(y_test, hybrid_binary):.4f}"
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, hybrid_binary))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        hybrid_binary,
        target_names=["NORMAL", "ATTACK"],
    )
)


# ============================================================
# HYBRID THREE-CLASS DISTRIBUTION
# ============================================================

print("\n")
print("=" * 80)
print("HYBRID THREE-CLASS DECISIONS")
print("=" * 80)

for label in ["NORMAL", "ATTACK", "SUSPICIOUS"]:

    count = (hybrid_text == label).sum()

    percentage = (
        count / len(hybrid_text)
    ) * 100

    print(
        f"{label:12s}: "
        f"{count:6d} "
        f"({percentage:6.2f}%)"
    )


# ============================================================
# MODEL DISAGREEMENT
# ============================================================

rf_normal_if_anomaly = (
    (rf_prediction == 0)
    & (if_prediction == 1)
).sum()

rf_attack_if_normal = (
    (rf_prediction == 1)
    & (if_prediction == 0)
).sum()

both_attack = (
    (rf_prediction == 1)
    & (if_prediction == 1)
).sum()

both_normal = (
    (rf_prediction == 0)
    & (if_prediction == 0)
).sum()


print("\n")
print("=" * 80)
print("MODEL AGREEMENT / DISAGREEMENT")
print("=" * 80)

print(
    f"Both NORMAL:          {both_normal}"
)

print(
    f"Both ATTACK:          {both_attack}"
)

print(
    f"RF NORMAL / IF ANOMALY:"
    f" {rf_normal_if_anomaly}"
)

print(
    f"RF ATTACK / IF NORMAL:"
    f" {rf_attack_if_normal}"
)


# ============================================================
# SAVE RESULTS
# ============================================================

results = test_df[
    ["label", "target"]
].copy()

results["rf_probability"] = rf_probability
results["rf_prediction"] = rf_prediction

results["if_score"] = if_score
results["if_prediction"] = if_prediction

results["hybrid_prediction"] = hybrid_prediction
results["hybrid_decision"] = hybrid_text

output_path = Path(
    "data/analysis/hybrid_ids_results.csv"
)

output_path.parent.mkdir(
    parents=True,
    exist_ok=True,
)

results.to_csv(
    output_path,
    index=False,
)

print("\nResults saved:")
print(output_path)
