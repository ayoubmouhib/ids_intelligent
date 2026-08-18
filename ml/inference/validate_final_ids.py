from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from predict import predict_traffic


TEST_PATH = Path("data/processed/nsl-kdd/test.csv")


print("=" * 80)
print("STEP 5C - FINAL IDS END-TO-END VALIDATION")
print("=" * 80)


# ============================================================
# LOAD TEST DATA
# ============================================================

print("\nLoading test dataset...")

test_df = pd.read_csv(TEST_PATH)

y_true = test_df["target"].values

print(f"Test samples: {len(test_df)}")


# ============================================================
# RUN SAVED IDS
# ============================================================

print("\nRunning saved IDS models...")

results = predict_traffic(test_df)

print("Inference complete.")


# ============================================================
# CONVERT HYBRID DECISIONS TO BINARY
# ============================================================

# ATTACK and SUSPICIOUS are considered security-positive
# for the binary evaluation.

y_pred = (
    results["decision"]
    .isin(["ATTACK", "SUSPICIOUS"])
    .astype(int)
    .values
)


# ============================================================
# OVERALL METRICS
# ============================================================

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


print("\n")
print("=" * 80)
print("FINAL IDS PERFORMANCE")
print("=" * 80)

print(f"Accuracy:         {accuracy:.4f}")
print(f"Attack Precision: {precision:.4f}")
print(f"Attack Recall:    {recall:.4f}")
print(f"Attack F1:        {f1:.4f}")


# ============================================================
# CONFUSION MATRIX
# ============================================================

cm = confusion_matrix(
    y_true,
    y_pred,
)


print("\nConfusion Matrix:")
print(cm)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\nClassification Report:")

print(
    classification_report(
        y_true,
        y_pred,
        target_names=[
            "NORMAL",
            "ATTACK",
        ],
        zero_division=0,
    )
)


# ============================================================
# DECISION DISTRIBUTION
# ============================================================

print("=" * 80)
print("DECISION DISTRIBUTION")
print("=" * 80)

decision_counts = (
    results["decision"]
    .value_counts()
)

print(decision_counts)


# ============================================================
# DECISION DISTRIBUTION BY TRUE CLASS
# ============================================================

print("\n")
print("=" * 80)
print("DECISIONS BY TRUE CLASS")
print("=" * 80)

analysis_df = pd.DataFrame(
    {
        "true_target": y_true,
        "decision": results["decision"],
    }
)

decision_by_class = pd.crosstab(
    analysis_df["true_target"],
    analysis_df["decision"],
)

decision_by_class.index = [
    "NORMAL",
    "ATTACK",
]

print(decision_by_class)


# ============================================================
# SAVE VALIDATION RESULTS
# ============================================================

output_dir = Path(
    "data/analysis"
)

output_dir.mkdir(
    parents=True,
    exist_ok=True,
)


summary = pd.DataFrame(
    [
        {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "normal": decision_counts.get(
                "NORMAL",
                0,
            ),
            "attack": decision_counts.get(
                "ATTACK",
                0,
            ),
            "suspicious": decision_counts.get(
                "SUSPICIOUS",
                0,
            ),
        }
    ]
)


summary_path = (
    output_dir
    / "final_ids_validation.csv"
)

summary.to_csv(
    summary_path,
    index=False,
)


print("\nValidation summary saved:")
print(f"  {summary_path}")


print("\n" + "=" * 80)
print("STEP 5C COMPLETE")
print("=" * 80)
