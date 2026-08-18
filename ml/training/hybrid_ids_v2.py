from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


# ============================================================
# PATHS
# ============================================================

TRAIN_PATH = Path(
    "data/processed/nsl-kdd/train.csv"
)

TEST_PATH = Path(
    "data/processed/nsl-kdd/test.csv"
)

OUTPUT_DIR = Path(
    "data/analysis"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# SELECTED THRESHOLDS
# ============================================================

RF_THRESHOLD = 0.40

# Isolation Forest decision_function:
#
# higher = more normal
# lower  = more anomalous
#
# We use the threshold selected in Step 4E.

IF_THRESHOLD = -0.10


# ============================================================
# FEATURES
# ============================================================

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

train_df = pd.read_csv(
    TRAIN_PATH
)

test_df = pd.read_csv(
    TEST_PATH
)


print(
    f"Training rows: {len(train_df)}"
)

print(
    f"Test rows:     {len(test_df)}"
)


X_train = train_df[
    FEATURE_COLUMNS
]

y_train = train_df[
    "target"
]

X_test = test_df[
    FEATURE_COLUMNS
]

y_test = test_df[
    "target"
]


# ============================================================
# PREPROCESSOR
# ============================================================

def create_preprocessor():

    return ColumnTransformer(
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

print("\n")
print("=" * 80)
print("TRAINING RANDOM FOREST")
print("=" * 80)


rf_model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
)


rf_pipeline = Pipeline(
    steps=[
        (
            "preprocessor",
            create_preprocessor(),
        ),
        (
            "model",
            rf_model,
        ),
    ]
)


rf_pipeline.fit(
    X_train,
    y_train,
)


print(
    "Random Forest training complete."
)


# ============================================================
# RANDOM FOREST PREDICTIONS
# ============================================================

print("\nPredicting with Random Forest...")

rf_probability = (
    rf_pipeline
    .predict_proba(X_test)[:, 1]
)


rf_attack = (
    rf_probability
    >= RF_THRESHOLD
)


print(
    "Random Forest prediction complete."
)


# ============================================================
# ISOLATION FOREST
# ============================================================

print("\n")
print("=" * 80)
print("TRAINING ISOLATION FOREST")
print("=" * 80)


normal_train_df = train_df[
    train_df["target"] == 0
].copy()


X_normal = normal_train_df[
    FEATURE_COLUMNS
]


print(
    f"Normal training samples: "
    f"{len(X_normal)}"
)


if_pipeline = Pipeline(
    steps=[
        (
            "preprocessor",
            create_preprocessor(),
        ),
        (
            "model",
            IsolationForest(
                n_estimators=200,
                contamination="auto",
                random_state=42,
                n_jobs=-1,
            ),
        ),
    ]
)


if_pipeline.fit(
    X_normal
)


print(
    "Isolation Forest training complete."
)


# ============================================================
# ISOLATION FOREST SCORES
# ============================================================

print("\nCalculating Isolation Forest scores...")

if_score = (
    if_pipeline
    .decision_function(X_test)
)


if_anomaly = (
    if_score <= IF_THRESHOLD
)


print(
    "Isolation Forest scoring complete."
)


# ============================================================
# INDIVIDUAL MODEL RESULTS
# ============================================================

rf_pred = rf_attack.astype(int)

if_pred = if_anomaly.astype(int)


def print_model_results(
    name,
    y_true,
    y_pred,
):

    print("\n")
    print("=" * 80)
    print(name)
    print("=" * 80)

    accuracy = accuracy_score(
        y_true,
        y_pred,
    )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    print(
        f"Accuracy:        {accuracy:.4f}"
    )

    print(
        f"Attack Precision:{precision:.4f}"
    )

    print(
        f"Attack Recall:   {recall:.4f}"
    )

    print(
        f"Attack F1:       {f1:.4f}"
    )

    print("\nConfusion Matrix:")

    print(
        confusion_matrix(
            y_true,
            y_pred,
        )
    )


print_model_results(
    "RANDOM FOREST",
    y_test,
    rf_pred,
)


print_model_results(
    "ISOLATION FOREST",
    y_test,
    if_pred,
)


# ============================================================
# HYBRID DECISION
# ============================================================
#
# Decision policy:
#
# 1. RF attack
#       -> ATTACK
#
# 2. RF normal + IF anomaly
#       -> SUSPICIOUS
#
# 3. RF normal + IF normal
#       -> NORMAL
#
# This intentionally does NOT automatically convert
# IF anomalies into binary ATTACK predictions.
#
# The goal is to use IF as a second-layer warning mechanism.
# ============================================================

hybrid_decision = np.full(
    len(test_df),
    "NORMAL",
    dtype=object,
)


# RF confidently detects attack
hybrid_decision[
    rf_attack
] = "ATTACK"


# RF says normal but IF finds anomaly
suspicious_mask = (
    (~rf_attack)
    & if_anomaly
)

hybrid_decision[
    suspicious_mask
] = "SUSPICIOUS"


# ============================================================
# DECISION DISTRIBUTION
# ============================================================

print("\n")
print("=" * 80)
print("HYBRID DECISION DISTRIBUTION")
print("=" * 80)


decision_distribution = (
    pd.Series(
        hybrid_decision
    )
    .value_counts()
)


print(
    decision_distribution
)


# ============================================================
# BINARY HYBRID EVALUATION
# ============================================================
#
# For a binary evaluation:
#
# ATTACK      -> attack
# SUSPICIOUS  -> attack
# NORMAL      -> normal
#
# This tells us what happens if the SOC treats every
# suspicious event as an attack alert.
# ============================================================

hybrid_binary = (
    hybrid_decision != "NORMAL"
).astype(int)


print_model_results(
    "HYBRID IDS - BINARY",
    y_test,
    hybrid_binary,
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        hybrid_binary,
        target_names=[
            "NORMAL",
            "ATTACK",
        ],
        zero_division=0,
    )
)


# ============================================================
# THREE-CLASS CONFUSION INFORMATION
# ============================================================

print("\n")
print("=" * 80)
print("HYBRID THREE-CLASS DECISIONS")
print("=" * 80)


for label in [
    "NORMAL",
    "ATTACK",
    "SUSPICIOUS",
]:

    count = int(
        np.sum(
            hybrid_decision == label
        )
    )

    percentage = (
        count / len(hybrid_decision)
    ) * 100

    print(
        f"{label:<12}: "
        f"{count:6d} "
        f"({percentage:6.2f}%)"
    )


# ============================================================
# MODEL AGREEMENT
# ============================================================

print("\n")
print("=" * 80)
print("MODEL AGREEMENT")
print("=" * 80)


both_normal = (
    (~rf_attack)
    & (~if_anomaly)
)

both_attack = (
    rf_attack
    & if_anomaly
)

rf_attack_if_normal = (
    rf_attack
    & (~if_anomaly)
)

rf_normal_if_anomaly = (
    (~rf_attack)
    & if_anomaly
)


print(
    f"Both NORMAL:          "
    f"{both_normal.sum()}"
)

print(
    f"Both ANOMALOUS:       "
    f"{both_attack.sum()}"
)

print(
    f"RF ATTACK / IF NORMAL:"
    f" {rf_attack_if_normal.sum()}"
)

print(
    f"RF NORMAL / IF ANOMALY:"
    f" {rf_normal_if_anomaly.sum()}"
)


# ============================================================
# ATTACK TYPE ANALYSIS
# ============================================================

attack_type_column = None

for column in [
    "attack_type",
    "label",
    "attack",
]:

    if column in test_df.columns:

        attack_type_column = column

        break


if attack_type_column is not None:

    attack_types = test_df[
        attack_type_column
    ]


    train_attack_types = set(
        train_df.loc[
            train_df["target"] == 1,
            attack_type_column,
        ].unique()
    )


    test_attack_types = set(
        attack_types.unique()
    )


    shared_attack_types = (
        train_attack_types
        & test_attack_types
    )


    test_only_attack_types = (
        test_attack_types
        - train_attack_types
    )


    # --------------------------------------------------------
    # ATTACK TYPE RESULTS
    # --------------------------------------------------------

    rows = []


    for attack_type in sorted(
        test_attack_types
    ):

        # Exclude NORMAL
        if attack_type == "normal":

            continue


        mask = (
            attack_types == attack_type
        )


        total = int(
            mask.sum()
        )


        rf_detected = int(
            rf_attack[mask].sum()
        )


        if_detected = int(
            if_anomaly[mask].sum()
        )


        hybrid_detected = int(
            hybrid_binary[mask].sum()
        )


        suspicious = int(
            (
                hybrid_decision[mask]
                == "SUSPICIOUS"
            ).sum()
        )


        rows.append(
            {
                "attack_type":
                    attack_type,

                "group":
                    (
                        "shared"
                        if attack_type
                        in shared_attack_types
                        else "test_only"
                    ),

                "total":
                    total,

                "rf_detected":
                    rf_detected,

                "rf_recall":
                    (
                        rf_detected / total
                        if total
                        else 0
                    ),

                "if_detected":
                    if_detected,

                "if_recall":
                    (
                        if_detected / total
                        if total
                        else 0
                    ),

                "hybrid_detected":
                    hybrid_detected,

                "hybrid_recall":
                    (
                        hybrid_detected / total
                        if total
                        else 0
                    ),

                "suspicious":
                    suspicious,
            }
        )


    attack_results = pd.DataFrame(
        rows
    )


    print("\n")
    print("=" * 80)
    print("ATTACK TYPE HYBRID ANALYSIS")
    print("=" * 80)


    print(
        attack_results.to_string(
            index=False,
            float_format=lambda x:
                f"{x:.4f}",
        )
    )


    # ========================================================
    # GROUP METRICS
    # ========================================================

    print("\n")
    print("=" * 80)
    print("SHARED VS TEST-ONLY ATTACKS")
    print("=" * 80)


    group_rows = []


    for group_name, group_types in [
        (
            "SHARED",
            shared_attack_types,
        ),
        (
            "TEST_ONLY",
            test_only_attack_types,
        ),
    ]:


        mask = (
            attack_types.isin(
                group_types
            )
            & (y_test == 1)
        )


        group_y = y_test[mask]

        group_rf = rf_pred[mask]

        group_if = if_pred[mask]

        group_hybrid = (
            hybrid_binary[mask]
        )


        group_rows.append(
            {
                "group":
                    group_name,

                "samples":
                    len(group_y),

                "rf_recall":
                    recall_score(
                        group_y,
                        group_rf,
                        zero_division=0,
                    ),

                "if_recall":
                    recall_score(
                        group_y,
                        group_if,
                        zero_division=0,
                    ),

                "hybrid_recall":
                    recall_score(
                        group_y,
                        group_hybrid,
                        zero_division=0,
                    ),

                "rf_f1":
                    f1_score(
                        group_y,
                        group_rf,
                        zero_division=0,
                    ),

                "if_f1":
                    f1_score(
                        group_y,
                        group_if,
                        zero_division=0,
                    ),

                "hybrid_f1":
                    f1_score(
                        group_y,
                        group_hybrid,
                        zero_division=0,
                    ),
            }
        )


    group_results = pd.DataFrame(
        group_rows
    )


    print(
        group_results.to_string(
            index=False,
            float_format=lambda x:
                f"{x:.4f}",
        )
    )


    # ========================================================
    # SAVE RESULTS
    # ========================================================

    attack_output = (
        OUTPUT_DIR
        / "hybrid_attack_analysis.csv"
    )


    attack_results.to_csv(
        attack_output,
        index=False,
    )


    group_output = (
        OUTPUT_DIR
        / "hybrid_group_comparison.csv"
    )


    group_results.to_csv(
        group_output,
        index=False,
    )


    print(
        f"\nSaved: {attack_output}"
    )

    print(
        f"Saved: {group_output}"
    )


# ============================================================
# SAVE SAMPLE-LEVEL RESULTS
# ============================================================

sample_results = test_df.copy()


sample_results[
    "rf_probability"
] = rf_probability


sample_results[
    "rf_prediction"
] = rf_pred


sample_results[
    "if_score"
] = if_score


sample_results[
    "if_prediction"
] = if_pred


sample_results[
    "hybrid_decision"
] = hybrid_decision


sample_output = (
    OUTPUT_DIR
    / "hybrid_ids_predictions.csv"
)


sample_results.to_csv(
    sample_output,
    index=False,
)


print(
    f"Saved: {sample_output}"
)


# ============================================================
# FINAL
# ============================================================

print("\n")
print("=" * 80)
print("STEP 4H COMPLETE")
print("=" * 80)

print(
    "\nHybrid IDS architecture:"
)

print(
    "  RF ATTACK + IF anything"
    "       -> ATTACK"
)

print(
    "  RF NORMAL + IF ANOMALY"
    "    -> SUSPICIOUS"
)

print(
    "  RF NORMAL + IF NORMAL"
    "      -> NORMAL"
)

print(
    "\nThe Isolation Forest is used"
    " as a complementary anomaly signal,"
)

print(
    "not as a replacement for the"
    " supervised Random Forest."
)
