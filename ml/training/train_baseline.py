from pathlib import Path

import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)

import json
from pathlib import Path

import matplotlib.pyplot as plt


# --------------------------------------------------
# Paths
# --------------------------------------------------

EVALUATION_DIR = Path("ml/evaluation")
EVALUATION_DIR.mkdir(parents=True, exist_ok=True)

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed" / "nsl-kdd"

TRAIN_FILE = DATA_DIR / "train.csv"
TEST_FILE = DATA_DIR / "test.csv"




# --------------------------------------------------
# Load data
# --------------------------------------------------

print("Loading datasets...")

train_df = pd.read_csv(TRAIN_FILE)
test_df = pd.read_csv(TEST_FILE)


# --------------------------------------------------
# Separate X and y
# --------------------------------------------------

X_train = train_df.drop(columns=["label", "target"])
y_train = train_df["target"]

X_test = test_df.drop(columns=["label", "target"])
y_test = test_df["target"]


# --------------------------------------------------
# Feature types
# --------------------------------------------------

categorical_features = [
    "protocol_type",
    "service",
    "flag",
]

numerical_features = [
    column
    for column in X_train.columns
    if column not in categorical_features
]


# --------------------------------------------------
# Preprocessor
# --------------------------------------------------

preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore",
                sparse_output=True,
            ),
            categorical_features,
        ),
        (
            "numerical",
            StandardScaler(),
            numerical_features,
        ),
    ],
)


# --------------------------------------------------
# Model
# --------------------------------------------------

model = LogisticRegression(
    max_iter=1000,
)


# --------------------------------------------------
# Complete ML pipeline
# --------------------------------------------------

pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("model", model),
    ]
)


# --------------------------------------------------
# Train
# --------------------------------------------------

print("Training model...")

pipeline.fit(X_train, y_train)


# --------------------------------------------------
# Evaluate basic accuracy
# --------------------------------------------------

y_pred = pipeline.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print(f"Test accuracy: {accuracy:.4f}")

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

fig, ax = plt.subplots()

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["NORMAL", "ATTACK"],
)

disp.plot(ax=ax)
ax.set_title("NSL-KDD Logistic Regression Confusion Matrix")

fig.savefig(
    EVALUATION_DIR / "confusion_matrix.png",
    bbox_inches="tight",
)

plt.close(fig)

report = classification_report(
    y_test,
    y_pred,
    target_names=["NORMAL", "ATTACK"],
)

print("\nClassification Report:")
print(report)

with open(EVALUATION_DIR / "classification_report.txt", "w") as f:
    f.write(report)

report_dict = classification_report(
    y_test,
    y_pred,
    target_names=["NORMAL", "ATTACK"],
    output_dict=True,
)

metrics = {
    "model": "logistic_regression",
    "dataset": "NSL-KDD",
    "accuracy": accuracy,
    "normal": {
        "precision": report_dict["NORMAL"]["precision"],
        "recall": report_dict["NORMAL"]["recall"],
        "f1_score": report_dict["NORMAL"]["f1-score"],
    },
    "attack": {
        "precision": report_dict["ATTACK"]["precision"],
        "recall": report_dict["ATTACK"]["recall"],
        "f1_score": report_dict["ATTACK"]["f1-score"],
    },
    "confusion_matrix": cm.tolist(),
}

with open(EVALUATION_DIR / "metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)