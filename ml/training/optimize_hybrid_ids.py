from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
TEST_PATH = Path("data/processed/nsl-kdd/test.csv")


# ============================================================
# CONFIGURATION
# ============================================================

RF_THRESHOLD = 0.40

IF_THRESHOLDS = [
    -0.15,
    -0.10,
    -0.05,
    0.00,
    0.05,
    0.10,
]


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
# LOAD DATA
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
# ATTACK TYPE GROUPS
# ============================================================

shared_attacks = sorted(
    set(
        train_df.loc[
            train_df["target"] == 1,
            "label"
        ]
    )
    &
    set(
        test_df.loc[
            test_df["target"] == 1,
            "label"
        ]
    )
)


test_only_attacks = sorted(
    set(
        test_df.loc[
            test_df["target"] == 1,
            "label"
        ]
    )
    -
    set(
        train_df.loc[
            train_df["target"] == 1,
            "label"
        ]
    )
)


print("\nAttack groups")
print("=" * 70)

print(f"Shared attacks:    {len(shared_attacks)}")
print(f"Test-only attacks: {len(test_only_attacks)}")


# ============================================================
# RANDOM FOREST
# ============================================================

print("\nTraining Random Forest...")

rf_preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore"
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


random_forest = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
)


rf_pipeline = Pipeline(
    steps=[
        (
            "preprocessor",
            rf_preprocessor,
        ),
        (
            "model",
            random_forest,
        ),
    ]
)


rf_pipeline.fit(
    X_train,
    y_train,
)


print("Random Forest training complete.")


print("\nCalculating Random Forest probabilities...")

rf_probabilities = rf_pipeline.predict_proba(X_test)[:, 1]

rf_predictions = (
    rf_probabilities >= RF_THRESHOLD
).astype(int)


# ============================================================
# ISOLATION FOREST
# ============================================================

print("\nPreparing normal traffic...")

normal_train_df = train_df[
    train_df["target"] == 0
].copy()


X_normal = normal_train_df[
    FEATURE_COLUMNS
]


print(
    f"Normal training samples: {len(X_normal)}"
)


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


isolation_forest = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)


if_pipeline = Pipeline(
    steps=[
        (
            "preprocessor",
            if_preprocessor,
        ),
        (
            "model",
            isolation_forest,
        ),
    ]
)


if_pipeline.fit(
    X_normal
)


print("Isolation Forest training complete.")


print(
    "\nCalculating Isolation Forest anomaly scores..."
)


decision_scores = if_pipeline.decision_function(
    X_test
)

# Higher anomaly score = more anomalous
anomaly_scores = -decision_scores


print("Anomaly scores calculated.")


# ============================================================
# BASELINE RANDOM FOREST RESULTS
# ============================================================

print("\n")
print("=" * 80)
print("RANDOM FOREST BASELINE")
print("=" * 80)


rf_accuracy = accuracy_score(
    y_test,
    rf_predictions,
)

rf_precision = precision_score(
    y_test,
    rf_predictions,
    zero_division=0,
)

rf_recall = recall_score(
    y_test,
    rf_predictions,
    zero_division=0,
)

rf_f1 = f1_score(
    y_test,
    rf_predictions,
    zero_division=0,
)


print(f"Accuracy:  {rf_accuracy:.4f}")
print(f"Precision: {rf_precision:.4f}")
print(f"Recall:    {rf_recall:.4f}")
print(f"F1:        {rf_f1:.4f}")


# ============================================================
# HYBRID THRESHOLD EXPERIMENT
# ============================================================

print("\n")
print("=" * 80)
print("HYBRID THRESHOLD EXPERIMENT")
print("=" * 80)


results = []


for if_threshold in IF_THRESHOLDS:

    # IF anomaly prediction
    if_anomaly = (
        anomaly_scores >= if_threshold
    ).astype(int)


    # --------------------------------------------------------
    # THREE-CLASS DECISION
    # --------------------------------------------------------

    decisions = np.full(
        len(y_test),
        "NORMAL",
        dtype=object,
    )


    # RF says attack
    decisions[
        rf_predictions == 1
    ] = "ATTACK"


    # RF says normal but IF says anomaly
    suspicious_mask = (
        (rf_predictions == 0)
        &
        (if_anomaly == 1)
    )


    decisions[
        suspicious_mask
    ] = "SUSPICIOUS"


    # --------------------------------------------------------
    # BINARY EVALUATION
    #
    # ATTACK and SUSPICIOUS are treated as positive
    # --------------------------------------------------------

    hybrid_binary = (
        decisions != "NORMAL"
    ).astype(int)


    accuracy = accuracy_score(
        y_test,
        hybrid_binary,
    )

    precision = precision_score(
        y_test,
        hybrid_binary,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        hybrid_binary,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        hybrid_binary,
        zero_division=0,
    )


    # --------------------------------------------------------
    # SHARED ATTACK RECALL
    # --------------------------------------------------------

    shared_mask = test_df[
        "label"
    ].isin(shared_attacks)


    shared_mask &= (
        y_test == 1
    )


    if shared_mask.sum() > 0:

        shared_recall = (
            hybrid_binary[shared_mask]
            .mean()
        )

    else:

        shared_recall = 0.0


    # --------------------------------------------------------
    # TEST-ONLY ATTACK RECALL
    # --------------------------------------------------------

    unseen_mask = test_df[
        "label"
    ].isin(test_only_attacks)


    unseen_mask &= (
        y_test == 1
    )


    if unseen_mask.sum() > 0:

        unseen_recall = (
            hybrid_binary[unseen_mask]
            .mean()
        )

    else:

        unseen_recall = 0.0


    # --------------------------------------------------------
    # SUSPICIOUS STATISTICS
    # --------------------------------------------------------

    suspicious_total = (
        decisions == "SUSPICIOUS"
    ).sum()


    suspicious_attacks = (
        (decisions == "SUSPICIOUS")
        &
        (y_test == 1)
    ).sum()


    suspicious_normals = (
        (decisions == "SUSPICIOUS")
        &
        (y_test == 0)
    ).sum()


    results.append(
        {
            "if_threshold": if_threshold,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "shared_recall": shared_recall,
            "test_only_recall": unseen_recall,
            "suspicious_total": suspicious_total,
            "suspicious_attacks": suspicious_attacks,
            "suspicious_normals": suspicious_normals,
        }
    )


    print(
        f"\nIF Threshold: {if_threshold:.2f}"
    )

    print(
        f"Accuracy:         {accuracy:.4f}"
    )

    print(
        f"Attack Precision: {precision:.4f}"
    )

    print(
        f"Attack Recall:    {recall:.4f}"
    )

    print(
        f"Attack F1:        {f1:.4f}"
    )

    print(
        f"Shared Recall:    {shared_recall:.4f}"
    )

    print(
        f"Test-only Recall: {unseen_recall:.4f}"
    )

    print(
        f"Suspicious total: {suspicious_total}"
    )

    print(
        f"  Attacks:        {suspicious_attacks}"
    )

    print(
        f"  Normals:        {suspicious_normals}"
    )


# ============================================================
# RESULTS
# ============================================================

results_df = pd.DataFrame(
    results
)


print("\n")
print("=" * 80)
print("HYBRID THRESHOLD COMPARISON")
print("=" * 80)

print(
    results_df.to_string(
        index=False
    )
)


# ============================================================
# BEST CONFIGURATION
# ============================================================

best_result = results_df.loc[
    results_df["f1"].idxmax()
]


print("\n")
print("=" * 80)
print("BEST HYBRID CONFIGURATION")
print("=" * 80)

print(
    f"IF threshold:      "
    f"{best_result['if_threshold']:.2f}"
)

print(
    f"Attack F1:         "
    f"{best_result['f1']:.4f}"
)

print(
    f"Attack Recall:     "
    f"{best_result['recall']:.4f}"
)

print(
    f"Attack Precision:  "
    f"{best_result['precision']:.4f}"
)

print(
    f"Shared Recall:     "
    f"{best_result['shared_recall']:.4f}"
)

print(
    f"Test-only Recall:  "
    f"{best_result['test_only_recall']:.4f}"
)

print(
    f"Suspicious total:  "
    f"{int(best_result['suspicious_total'])}"
)


# ============================================================
# SAVE RESULTS
# ============================================================

OUTPUT_PATH = Path(
    "data/analysis/hybrid_threshold_experiment.csv"
)


OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)


results_df.to_csv(
    OUTPUT_PATH,
    index=False,
)


print(
    f"\nSaved: {OUTPUT_PATH}"
)


print("\n")
print("=" * 80)
print("STEP 5A COMPLETE")
print("=" * 80)
