from pathlib import Path

import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline


TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
TEST_PATH = Path("data/processed/nsl-kdd/test.csv")

OUTPUT_SHARED = Path(
    "data/analysis/anomaly_shared_attack_evaluation.csv"
)

OUTPUT_UNSEEN = Path(
    "data/analysis/anomaly_unseen_attack_evaluation.csv"
)


# ============================================================
# CONFIGURATION
# ============================================================

THRESHOLD = -0.10


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


# ============================================================
# 2. IDENTIFY ATTACK TYPES
# ============================================================

training_attack_types = set(
    train_df.loc[
        train_df["target"] == 1,
        "label",
    ]
)

test_attack_types = set(
    test_df.loc[
        test_df["target"] == 1,
        "label",
    ]
)

shared_attack_types = sorted(
    training_attack_types.intersection(
        test_attack_types
    )
)

test_only_attack_types = sorted(
    test_attack_types.difference(
        training_attack_types
    )
)


print("\nAttack type summary")
print("=" * 70)

print(
    f"Training attack types: {len(training_attack_types)}"
)

print(
    f"Test attack types:     {len(test_attack_types)}"
)

print(
    f"Shared attack types:   {len(shared_attack_types)}"
)

print(
    f"Test-only attacks:     {len(test_only_attack_types)}"
)


# ============================================================
# 3. TRAIN ISOLATION FOREST ON NORMAL TRAFFIC
# ============================================================

normal_train_df = train_df[
    train_df["target"] == 0
].copy()

X_train = normal_train_df[FEATURE_COLUMNS]

X_test = test_df[FEATURE_COLUMNS]

print(
    f"\nNormal training samples: {len(X_train)}"
)


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


print("\nTraining Isolation Forest...")

pipeline.fit(X_train)

print("Training complete.")


# ============================================================
# 4. PREDICT TEST DATA
# ============================================================

print("\nPredicting test data...")

decision_scores = pipeline.decision_function(X_test)

# Isolation Forest:
#
# higher decision score = more normal
# lower decision score  = more anomalous
#
# Invert the score so:
#
# higher anomaly score = more anomalous

anomaly_scores = -decision_scores

y_pred = (
    anomaly_scores >= THRESHOLD
).astype(int)


print("Prediction complete.")


# ============================================================
# 5. ADD RESULTS TO TEST DATA
# ============================================================

results_df = test_df[
    ["label", "target"]
].copy()

results_df["prediction"] = y_pred

results_df["anomaly_score"] = anomaly_scores


# ============================================================
# 6. FUNCTION TO ANALYZE ATTACK GROUP
# ============================================================

def analyze_attack_types(
    attack_types,
    title,
):
    rows = []

    attack_df = results_df[
        results_df["label"].isin(attack_types)
    ]

    for attack_type in sorted(attack_types):

        subset = attack_df[
            attack_df["label"] == attack_type
        ]

        total = len(subset)

        detected = int(
            (subset["prediction"] == 1).sum()
        )

        missed = total - detected

        recall = (
            detected / total
            if total > 0
            else 0.0
        )

        rows.append(
            {
                "attack_type": attack_type,
                "total": total,
                "detected": detected,
                "missed": missed,
                "recall": recall,
            }
        )

    report = pd.DataFrame(rows)

    print("\n")
    print("=" * 80)
    print(title)
    print("=" * 80)

    if report.empty:
        print("No attacks found.")
        return report

    print(
        report.to_string(
            index=False,
            formatters={
                "recall": "{:.4f}".format
            },
        )
    )

    return report


# ============================================================
# 7. SHARED ATTACK EVALUATION
# ============================================================

shared_report = analyze_attack_types(
    shared_attack_types,
    "SHARED ATTACK EVALUATION",
)


# ============================================================
# 8. TEST-ONLY ATTACK EVALUATION
# ============================================================

unseen_report = analyze_attack_types(
    test_only_attack_types,
    "TEST-ONLY ATTACK EVALUATION",
)


# ============================================================
# 9. OVERALL GROUP METRICS
# ============================================================

def calculate_group_metrics(
    attack_types,
):

    subset = results_df[
        results_df["label"].isin(attack_types)
    ]

    y_true = subset["target"]
    y_pred_group = subset["prediction"]

    precision = precision_score(
        y_true,
        y_pred_group,
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        y_pred_group,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        y_pred_group,
        zero_division=0,
    )

    return (
        len(subset),
        int((y_pred_group == 1).sum()),
        int((y_pred_group == 0).sum()),
        precision,
        recall,
        f1,
    )


shared_metrics = calculate_group_metrics(
    shared_attack_types
)

unseen_metrics = calculate_group_metrics(
    test_only_attack_types
)


print("\n")
print("=" * 80)
print("GROUP COMPARISON")
print("=" * 80)

print("\nSHARED ATTACKS")

print(
    f"Samples:         {shared_metrics[0]}"
)

print(
    f"Detected:        {shared_metrics[1]}"
)

print(
    f"Missed:          {shared_metrics[2]}"
)

print(
    f"Attack precision: {shared_metrics[3]:.4f}"
)

print(
    f"Attack recall:    {shared_metrics[4]:.4f}"
)

print(
    f"Attack F1:        {shared_metrics[5]:.4f}"
)


print("\nTEST-ONLY ATTACKS")

print(
    f"Samples:         {unseen_metrics[0]}"
)

print(
    f"Detected:        {unseen_metrics[1]}"
)

print(
    f"Missed:          {unseen_metrics[2]}"
)

print(
    f"Attack precision: {unseen_metrics[3]:.4f}"
)

print(
    f"Attack recall:    {unseen_metrics[4]:.4f}"
)

print(
    f"Attack F1:        {unseen_metrics[5]:.4f}"
)


# ============================================================
# 10. SAVE RESULTS
# ============================================================

OUTPUT_SHARED.parent.mkdir(
    parents=True,
    exist_ok=True,
)

shared_report.to_csv(
    OUTPUT_SHARED,
    index=False,
)

unseen_report.to_csv(
    OUTPUT_UNSEEN,
    index=False,
)


print("\nResults saved:")

print(
    f"  {OUTPUT_SHARED}"
)

print(
    f"  {OUTPUT_UNSEEN}"
)

print("\nStep 4F complete.")
