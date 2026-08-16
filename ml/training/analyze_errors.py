from pathlib import Path

import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


# ============================================================
# Paths
# ============================================================

TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
TEST_PATH = Path("data/processed/nsl-kdd/test.csv")


# ============================================================
# Features
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
# Load data
# ============================================================

print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)


# ============================================================
# Prepare training data
# ============================================================

X = train_df[FEATURE_COLUMNS]
y = train_df["target"]

X_test = test_df[FEATURE_COLUMNS]
y_test = test_df["target"]


# ============================================================
# Train / validation split
# ============================================================

X_train, X_val, y_train, y_val = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)


# ============================================================
# Preprocessor
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
# Random Forest
# ============================================================

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


# ============================================================
# Train
# ============================================================

print("Training Random Forest...")

pipeline.fit(X_train, y_train)

print("Training complete.")


# ============================================================
# Predict on official test set
# ============================================================

print("Predicting test data...")

y_test_proba = pipeline.predict_proba(X_test)[:, 1]


# We selected 0.40 using the validation set.
threshold = 0.40

y_test_pred = (
    y_test_proba >= threshold
).astype(int)


# ============================================================
# Add predictions to test dataframe
# ============================================================

analysis_df = test_df.copy()

analysis_df["predicted"] = y_test_pred

analysis_df["correct"] = (
    analysis_df["target"]
    == analysis_df["predicted"]
)


# ============================================================
# Analyze attacks only
# ============================================================

attacks = analysis_df[
    analysis_df["target"] == 1
].copy()


print("\nAttack error analysis")
print("=" * 80)


# ============================================================
# Calculate statistics per attack type
# ============================================================

results = []


for attack_type, group in attacks.groupby("label"):

    total = len(group)

    detected = (
        group["predicted"] == 1
    ).sum()

    missed = (
        group["predicted"] == 0
    ).sum()

    recall = detected / total

    results.append(
        {
            "attack_type": attack_type,
            "total": total,
            "detected": detected,
            "missed": missed,
            "recall": recall,
        }
    )


results_df = pd.DataFrame(results)


# Sort by number of missed attacks

results_df = results_df.sort_values(
    by="missed",
    ascending=False,
)


# ============================================================
# Display results
# ============================================================

print(
    results_df.to_string(
        index=False,
        formatters={
            "recall": "{:.4f}".format,
        },
    )
)


# ============================================================
# Total false negatives
# ============================================================

false_negatives = analysis_df[
    (analysis_df["target"] == 1)
    & (analysis_df["predicted"] == 0)
]


print("\nTotal missed attacks:")
print(len(false_negatives))


# ============================================================
# Top 10 attack types responsible for missed attacks
# ============================================================

print("\nTop attack types by missed attacks")
print("=" * 80)


top_missed = (
    results_df
    .sort_values(
        by="missed",
        ascending=False,
    )
    .head(10)
)


print(
    top_missed.to_string(
        index=False,
        formatters={
            "recall": "{:.4f}".format,
        },
    )
)