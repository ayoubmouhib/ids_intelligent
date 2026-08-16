from pathlib import Path

import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
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


# ---------------------------------------------------------
# 1. LOAD DATA
# ---------------------------------------------------------

print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

print(f"Training rows: {len(train_df)}")
print(f"Test rows:     {len(test_df)}")


# ---------------------------------------------------------
# 2. FIND ATTACK TYPES
# ---------------------------------------------------------

training_attacks = set(
    train_df.loc[train_df["target"] == 1, "label"].unique()
)

test_attacks = set(
    test_df.loc[test_df["target"] == 1, "label"].unique()
)

shared_attacks = training_attacks & test_attacks
test_only_attacks = test_attacks - training_attacks


print("\nAttack type summary")
print("=" * 70)

print(f"Training attack types: {len(training_attacks)}")
print(f"Test attack types:     {len(test_attacks)}")
print(f"Shared attack types:   {len(shared_attacks)}")
print(f"Test-only attacks:     {len(test_only_attacks)}")


print("\nShared attacks:")
for attack in sorted(shared_attacks):
    print(f"  {attack}")


print("\nTest-only attacks:")
for attack in sorted(test_only_attacks):
    print(f"  {attack}")


# ---------------------------------------------------------
# 3. PREPARE TRAINING DATA
# ---------------------------------------------------------

X_train = train_df[FEATURE_COLUMNS]
y_train = train_df["target"]


X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["target"]


# ---------------------------------------------------------
# 4. PREPROCESSOR
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# 5. RANDOM FOREST
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# 6. TRAIN
# ---------------------------------------------------------

print("\nTraining Random Forest...")

pipeline.fit(X_train, y_train)

print("Training complete.")


# ---------------------------------------------------------
# 7. PREDICT TEST DATA
# ---------------------------------------------------------

print("\nPredicting test data...")

y_proba = pipeline.predict_proba(X_test)[:, 1]

# Use the threshold we selected earlier.
THRESHOLD = 0.40

y_pred = (y_proba >= THRESHOLD).astype(int)


# ---------------------------------------------------------
# 8. SHARED ATTACK EVALUATION
# ---------------------------------------------------------

shared_mask = (
    (test_df["target"] == 1)
    & (test_df["label"].isin(shared_attacks))
)

y_shared_true = y_test[shared_mask]
y_shared_pred = y_pred[shared_mask]


print("\n")
print("=" * 80)
print("SHARED ATTACK EVALUATION")
print("=" * 80)

print(f"Samples: {len(y_shared_true)}")

print(
    f"Attack recall: "
    f"{recall_score(y_shared_true, y_shared_pred):.4f}"
)

print(
    f"Attack precision: "
    f"{precision_score(y_shared_true, y_shared_pred):.4f}"
)

print(
    f"Attack F1: "
    f"{f1_score(y_shared_true, y_shared_pred):.4f}"
)


# ---------------------------------------------------------
# 9. SHARED ATTACK RECALL BY TYPE
# ---------------------------------------------------------

print("\nShared attack recall by type")
print("-" * 80)

shared_results = []

for attack in sorted(shared_attacks):

    mask = (
        (test_df["label"] == attack)
        & (test_df["target"] == 1)
    )

    total = mask.sum()

    detected = y_pred[mask].sum()

    missed = total - detected

    recall = detected / total if total > 0 else 0.0

    shared_results.append(
        {
            "attack_type": attack,
            "total": int(total),
            "detected": int(detected),
            "missed": int(missed),
            "recall": recall,
        }
    )

shared_results_df = pd.DataFrame(shared_results)

print(
    shared_results_df.to_string(
        index=False,
        formatters={
            "recall": "{:.4f}".format
        },
    )
)


# ---------------------------------------------------------
# 10. TEST-ONLY ATTACK EVALUATION
# ---------------------------------------------------------

test_only_mask = (
    (test_df["target"] == 1)
    & (test_df["label"].isin(test_only_attacks))
)

y_unseen_true = y_test[test_only_mask]
y_unseen_pred = y_pred[test_only_mask]


print("\n")
print("=" * 80)
print("TEST-ONLY ATTACK EVALUATION")
print("=" * 80)

print(f"Samples: {len(y_unseen_true)}")

print(
    f"Attack detection rate: "
    f"{recall_score(y_unseen_true, y_unseen_pred):.4f}"
)

print(
    f"Attack precision: "
    f"{precision_score(y_unseen_true, y_unseen_pred):.4f}"
)

print(
    f"Attack F1: "
    f"{f1_score(y_unseen_true, y_unseen_pred):.4f}"
)


# ---------------------------------------------------------
# 11. TEST-ONLY RECALL BY TYPE
# ---------------------------------------------------------

print("\nTest-only attack detection by type")
print("-" * 80)

unseen_results = []

for attack in sorted(test_only_attacks):

    mask = (
        (test_df["label"] == attack)
        & (test_df["target"] == 1)
    )

    total = mask.sum()

    detected = y_pred[mask].sum()

    missed = total - detected

    recall = detected / total if total > 0 else 0.0

    unseen_results.append(
        {
            "attack_type": attack,
            "total": int(total),
            "detected": int(detected),
            "missed": int(missed),
            "recall": recall,
        }
    )

unseen_results_df = pd.DataFrame(unseen_results)

print(
    unseen_results_df.to_string(
        index=False,
        formatters={
            "recall": "{:.4f}".format
        },
    )
)


# ---------------------------------------------------------
# 12. SAVE RESULTS
# ---------------------------------------------------------

analysis_dir = Path("data/analysis")
analysis_dir.mkdir(parents=True, exist_ok=True)


shared_results_df.to_csv(
    analysis_dir / "shared_attack_evaluation.csv",
    index=False,
)

unseen_results_df.to_csv(
    analysis_dir / "unseen_attack_evaluation.csv",
    index=False,
)


print("\nResults saved:")
print(
    "  data/analysis/shared_attack_evaluation.csv"
)
print(
    "  data/analysis/unseen_attack_evaluation.csv"
)
