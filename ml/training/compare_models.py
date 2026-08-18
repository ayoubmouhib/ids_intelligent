from pathlib import Path

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

TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
TEST_PATH = Path("data/processed/nsl-kdd/test.csv")

OUTPUT_DIR = Path("data/analysis")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# CONFIGURATION
# ============================================================

RF_THRESHOLD = 0.40

# Isolation Forest uses decision_function:
#
# higher  = more normal
# lower   = more anomalous
#
# Therefore:
#
# score <= -0.10 -> ATTACK
#
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

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

print(f"Training rows: {len(train_df)}")
print(f"Test rows:     {len(test_df)}")


X_train = train_df[FEATURE_COLUMNS]
y_train = train_df["target"]

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["target"]


# ============================================================
# PREPROCESSOR
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
        ("preprocessor", preprocessor),
        ("model", rf_model),
    ]
)

rf_pipeline.fit(X_train, y_train)

print("Random Forest training complete.")


# ============================================================
# RANDOM FOREST PREDICTIONS
# ============================================================

print("\nPredicting with Random Forest...")

rf_probability = rf_pipeline.predict_proba(X_test)[:, 1]

rf_pred = (
    rf_probability >= RF_THRESHOLD
).astype(int)


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

print("Isolation Forest training complete.")


# ============================================================
# ISOLATION FOREST PREDICTIONS
# ============================================================

print("\nPredicting with Isolation Forest...")

if_scores = if_pipeline.decision_function(X_test)

if_pred = (
    if_scores <= IF_THRESHOLD
).astype(int)


# ============================================================
# METRIC FUNCTION
# ============================================================

def calculate_metrics(y_true, y_pred):
    return {
        "accuracy": accuracy_score(
            y_true,
            y_pred,
        ),
        "precision": precision_score(
            y_true,
            y_pred,
            zero_division=0,
        ),
        "recall": recall_score(
            y_true,
            y_pred,
            zero_division=0,
        ),
        "f1": f1_score(
            y_true,
            y_pred,
            zero_division=0,
        ),
    }


# ============================================================
# OVERALL COMPARISON
# ============================================================

rf_metrics = calculate_metrics(
    y_test,
    rf_pred,
)

if_metrics = calculate_metrics(
    y_test,
    if_pred,
)


print("\n")
print("=" * 80)
print("STEP 4G - MODEL COMPARISON")
print("=" * 80)


comparison_df = pd.DataFrame(
    [
        {
            "model": "Random Forest",
            "threshold": RF_THRESHOLD,
            **rf_metrics,
        },
        {
            "model": "Isolation Forest",
            "threshold": IF_THRESHOLD,
            **if_metrics,
        },
    ]
)


print("\nOverall performance")
print("-" * 80)

print(
    comparison_df.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}",
    )
)


# ============================================================
# CONFUSION MATRICES
# ============================================================

print("\n")
print("=" * 80)
print("RANDOM FOREST CONFUSION MATRIX")
print("=" * 80)

print(
    confusion_matrix(
        y_test,
        rf_pred,
    )
)


print("\n")
print("=" * 80)
print("ISOLATION FOREST CONFUSION MATRIX")
print("=" * 80)

print(
    confusion_matrix(
        y_test,
        if_pred,
    )
)


# ============================================================
# CLASSIFICATION REPORTS
# ============================================================

print("\n")
print("=" * 80)
print("RANDOM FOREST CLASSIFICATION REPORT")
print("=" * 80)

print(
    classification_report(
        y_test,
        rf_pred,
        target_names=[
            "NORMAL",
            "ATTACK",
        ],
        zero_division=0,
    )
)


print("\n")
print("=" * 80)
print("ISOLATION FOREST CLASSIFICATION REPORT")
print("=" * 80)

print(
    classification_report(
        y_test,
        if_pred,
        target_names=[
            "NORMAL",
            "ATTACK",
        ],
        zero_division=0,
    )
)


# ============================================================
# ATTACK TYPE INFORMATION
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


if attack_type_column is None:

    print("\n")
    print("=" * 80)
    print("WARNING")
    print("=" * 80)

    print(
        "No attack type column was found."
    )

    print(
        "Skipping per-attack comparison."
    )

else:

    attack_types = test_df[
        attack_type_column
    ]

    # --------------------------------------------------------
    # SHARED / TEST-ONLY ATTACK TYPES
    # --------------------------------------------------------

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

    print("\n")
    print("=" * 80)
    print("ATTACK TYPE GROUPS")
    print("=" * 80)

    print(
        f"Shared attack types:   "
        f"{len(shared_attack_types)}"
    )

    print(
        f"Test-only attack types: "
        f"{len(test_only_attack_types)}"
    )


    # ========================================================
    # PER ATTACK TYPE
    # ========================================================

    rows = []

    for attack_type in sorted(
        test_attack_types
    ):

        mask = (
            attack_types == attack_type
        )

        y_attack = y_test[mask]

        rf_attack_pred = rf_pred[mask]

        if_attack_pred = if_pred[mask]


        # Only attacks should be measured here.
        total = len(y_attack)

        rf_detected = int(
            rf_attack_pred.sum()
        )

        if_detected = int(
            if_attack_pred.sum()
        )


        rows.append(
            {
                "attack_type": attack_type,
                "group": (
                    "shared"
                    if attack_type
                    in shared_attack_types
                    else "test_only"
                ),
                "total": total,
                "rf_detected": rf_detected,
                "rf_missed": (
                    total - rf_detected
                ),
                "rf_recall": (
                    rf_detected / total
                    if total > 0
                    else 0
                ),
                "if_detected": if_detected,
                "if_missed": (
                    total - if_detected
                ),
                "if_recall": (
                    if_detected / total
                    if total > 0
                    else 0
                ),
            }
        )


    attack_comparison_df = pd.DataFrame(
        rows
    )


    # ========================================================
    # SHARED ATTACK SUMMARY
    # ========================================================

    shared_mask = (
        attack_types.isin(
            shared_attack_types
        )
        & (y_test == 1)
    )

    shared_y = y_test[shared_mask]

    shared_rf = rf_pred[shared_mask]

    shared_if = if_pred[shared_mask]


    shared_rf_metrics = calculate_metrics(
        shared_y,
        shared_rf,
    )

    shared_if_metrics = calculate_metrics(
        shared_y,
        shared_if,
    )


    # ========================================================
    # TEST-ONLY ATTACK SUMMARY
    # ========================================================

    unseen_mask = (
        attack_types.isin(
            test_only_attack_types
        )
        & (y_test == 1)
    )

    unseen_y = y_test[unseen_mask]

    unseen_rf = rf_pred[unseen_mask]

    unseen_if = if_pred[unseen_mask]


    unseen_rf_metrics = calculate_metrics(
        unseen_y,
        unseen_rf,
    )

    unseen_if_metrics = calculate_metrics(
        unseen_y,
        unseen_if,
    )


    # ========================================================
    # GROUP COMPARISON
    # ========================================================

    group_comparison = pd.DataFrame(
        [
            {
                "group": "shared_attacks",
                "samples": len(shared_y),
                "rf_recall": shared_rf_metrics[
                    "recall"
                ],
                "rf_f1": shared_rf_metrics[
                    "f1"
                ],
                "if_recall": shared_if_metrics[
                    "recall"
                ],
                "if_f1": shared_if_metrics[
                    "f1"
                ],
            },
            {
                "group": "test_only_attacks",
                "samples": len(unseen_y),
                "rf_recall": unseen_rf_metrics[
                    "recall"
                ],
                "rf_f1": unseen_rf_metrics[
                    "f1"
                ],
                "if_recall": unseen_if_metrics[
                    "recall"
                ],
                "if_f1": unseen_if_metrics[
                    "f1"
                ],
            },
        ]
    )


    print("\n")
    print("=" * 80)
    print("SHARED VS TEST-ONLY ATTACKS")
    print("=" * 80)

    print(
        group_comparison.to_string(
            index=False,
            float_format=lambda x: f"{x:.4f}",
        )
    )


    # ========================================================
    # PER ATTACK TYPE
    # ========================================================

    print("\n")
    print("=" * 80)
    print("PER-ATTACK TYPE COMPARISON")
    print("=" * 80)

    print(
        attack_comparison_df.to_string(
            index=False,
            float_format=lambda x: f"{x:.4f}",
        )
    )


    # ========================================================
    # SAVE PER ATTACK RESULTS
    # ========================================================

    attack_output = (
        OUTPUT_DIR
        / "rf_vs_if_attack_comparison.csv"
    )

    attack_comparison_df.to_csv(
        attack_output,
        index=False,
    )

    print(
        f"\nSaved: {attack_output}"
    )


    # ========================================================
    # SAVE GROUP RESULTS
    # ========================================================

    group_output = (
        OUTPUT_DIR
        / "rf_vs_if_group_comparison.csv"
    )

    group_comparison.to_csv(
        group_output,
        index=False,
    )

    print(
        f"Saved: {group_output}"
    )


# ============================================================
# SAVE OVERALL RESULTS
# ============================================================

overall_output = (
    OUTPUT_DIR
    / "rf_vs_if_model_comparison.csv"
)

comparison_df.to_csv(
    overall_output,
    index=False,
)

print(
    f"\nSaved: {overall_output}"
)


# ============================================================
# FINAL CONCLUSION
# ============================================================

print("\n")
print("=" * 80)
print("STEP 4G COMPLETE")
print("=" * 80)

print(
    "\nThe comparison is now complete."
)

print(
    "\nRandom Forest:"
)

print(
    f"  Attack recall: "
    f"{rf_metrics['recall']:.4f}"
)

print(
    f"  Attack F1:     "
    f"{rf_metrics['f1']:.4f}"
)

print(
    "\nIsolation Forest:"
)

print(
    f"  Attack recall: "
    f"{if_metrics['recall']:.4f}"
)

print(
    f"  Attack F1:     "
    f"{if_metrics['f1']:.4f}"
)

print(
    "\nNext step: Step 4H - design the hybrid IDS decision strategy."
)
