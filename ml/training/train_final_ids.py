from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


# ============================================================
# PATHS
# ============================================================

TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
MODEL_DIR = Path("models")

MODEL_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# FINAL CONFIGURATION
# ============================================================

RF_THRESHOLD = 0.40
IF_THRESHOLD = -0.10

RANDOM_STATE = 42


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

print("=" * 80)
print("FINAL IDS TRAINING")
print("=" * 80)

print("\nLoading training dataset...")

train_df = pd.read_csv(TRAIN_PATH)

print(f"Training shape: {train_df.shape}")


X = train_df[FEATURE_COLUMNS]
y = train_df["target"]


# ============================================================
# RANDOM FOREST
# ============================================================

print("\n" + "=" * 80)
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
    n_estimators=300,
    random_state=RANDOM_STATE,
    n_jobs=-1,
    class_weight="balanced",
)


rf_pipeline = Pipeline(
    steps=[
        ("preprocessor", rf_preprocessor),
        ("model", rf_model),
    ]
)


rf_pipeline.fit(X, y)

print("Random Forest training complete.")


# ============================================================
# ISOLATION FOREST
# ============================================================

print("\n" + "=" * 80)
print("TRAINING ISOLATION FOREST")
print("=" * 80)

normal_df = train_df[train_df["target"] == 0].copy()

X_normal = normal_df[FEATURE_COLUMNS]

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
    random_state=RANDOM_STATE,
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
# SAVE MODELS
# ============================================================

print("\n" + "=" * 80)
print("SAVING FINAL IDS MODELS")
print("=" * 80)

rf_path = MODEL_DIR / "random_forest_final.joblib"
if_path = MODEL_DIR / "isolation_forest_final.joblib"
config_path = MODEL_DIR / "ids_config.joblib"


joblib.dump(
    rf_pipeline,
    rf_path,
)

joblib.dump(
    if_pipeline,
    if_path,
)

joblib.dump(
    {
        "rf_threshold": RF_THRESHOLD,
        "if_threshold": IF_THRESHOLD,
        "random_state": RANDOM_STATE,
        "feature_columns": FEATURE_COLUMNS,
        "categorical_features": CATEGORICAL_FEATURES,
        "numerical_features": NUMERICAL_FEATURES,
    },
    config_path,
)


print(f"\nRandom Forest:")
print(f"  {rf_path}")

print(f"\nIsolation Forest:")
print(f"  {if_path}")

print(f"\nConfiguration:")
print(f"  {config_path}")


# ============================================================
# FINAL CONFIGURATION SUMMARY
# ============================================================

print("\n" + "=" * 80)
print("FINAL IDS CONFIGURATION")
print("=" * 80)

print(f"Random Forest threshold:  {RF_THRESHOLD:.2f}")
print(f"Isolation Forest threshold: {IF_THRESHOLD:.2f}")

print("\nDecision policy:")
print("  RF ATTACK + IF anything  -> ATTACK")
print("  RF NORMAL + IF ANOMALY    -> SUSPICIOUS")
print("  RF NORMAL + IF NORMAL     -> NORMAL")

print("\nStep 5A complete.")
