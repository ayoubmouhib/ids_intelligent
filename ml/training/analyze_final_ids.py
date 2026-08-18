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


# ============================================================
# PATHS
# ============================================================

TEST_PATH = Path("data/processed/nsl-kdd/test.csv")
PREDICTIONS_PATH = Path("data/analysis/final_ids_predictions.csv")

OUTPUT_DIR = Path("data/analysis")

ATTACK_TYPE_COLUMN = "attack_type"
TARGET_COLUMN = "target"


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 80)
print("STEP 5D - FINAL IDS ANALYSIS")
print("=" * 80)

print("\nLoading test dataset...")
test_df = pd.read_csv(TEST_PATH)

print(f"Test samples: {len(test_df)}")

print("\nLoading final IDS predictions...")
pred_df = pd.read_csv(PREDICTIONS_PATH)

print(f"Prediction samples: {len(pred_df)}")


# ============================================================
# VALIDATE ALIGNMENT
# ============================================================

if len(test_df) != len(pred_df):
    raise ValueError(
        "Test dataset and prediction file contain different "
        "numbers of rows."
    )


print("Prediction alignment verified.")


# ============================================================
# 1. EXTRACT TRUE LABELS
# ============================================================

y_true = test_df[TARGET_COLUMN].astype(int)

# The final inference file contains the final IDS decision.
#
# NORMAL      -> 0
# ATTACK      -> 1
# SUSPICIOUS  -> special IDS state
#
# For binary evaluation:
#
# ATTACK      -> 1
# NORMAL      -> 0
# SUSPICIOUS  -> 1
#
# A suspicious event is treated as an attack for the
# security-oriented binary evaluation.

decision = pred_df["decision"].astype(str)

y_pred_binary = decision.isin(
    ["ATTACK", "SUSPICIOUS"]
).astype(int)


# ============================================================
# 2. OVERALL PERFORMANCE
# ============================================================

print("\n")
print("=" * 80)
print("FINAL IDS OVERALL PERFORMANCE")
print("=" * 80)

accuracy = accuracy_score(
    y_true,
    y_pred_binary,
)

precision = precision_score(
    y_true,
    y_pred_binary,
    zero_division=0,
)

recall = recall_score(
    y_true,
    y_pred_binary,
    zero_division=0,
)

f1 = f1_score(
    y_true,
    y_pred_binary,
    zero_division=0,
)


print(f"Accuracy:         {accuracy:.4f}")
print(f"Attack Precision: {precision:.4f}")
print(f"Attack Recall:    {recall:.4f}")
print(f"Attack F1:        {f1:.4f}")


# ============================================================
# 3. CONFUSION MATRIX
# ============================================================

cm = confusion_matrix(
    y_true,
    y_pred_binary,
)

print("\n")
print("=" * 80)
print("FINAL IDS CONFUSION MATRIX")
print("=" * 80)

print(cm)


# ============================================================
# 4. CLASSIFICATION REPORT
# ============================================================

print("\n")
print("=" * 80)
print("FINAL IDS CLASSIFICATION REPORT")
print("=" * 80)

print(
    classification_report(
        y_true,
        y_pred_binary,
        target_names=["NORMAL", "ATTACK"],
        zero_division=0,
    )
)


# ============================================================
# 5. THREE-CLASS DECISION DISTRIBUTION
# ============================================================

print("\n")
print("=" * 80)
print("FINAL IDS DECISION DISTRIBUTION")
print("=" * 80)

decision_distribution = (
    decision.value_counts()
    .rename_axis("decision")
    .reset_index(name="samples")
)

decision_distribution["percentage"] = (
    decision_distribution["samples"]
    / len(decision)
    * 100
)

print(
    decision_distribution.to_string(
        index=False,
        formatters={
            "percentage": "{:.2f}".format,
        },
    )
)


# ============================================================
# 6. DECISIONS BY TRUE CLASS
# ============================================================

print("\n")
print("=" * 80)
print("DECISIONS BY TRUE CLASS")
print("=" * 80)

decision_by_true_class = pd.crosstab(
    y_true.map(
        {
            0: "NORMAL",
            1: "ATTACK",
        }
    ),
    decision,
)

print(decision_by_true_class)


# ============================================================
# 7. ADD IDS RESULTS TO TEST DATA
# ============================================================

analysis_df = test_df.copy()

analysis_df["ids_decision"] = decision.values

analysis_df["ids_binary_prediction"] = (
    y_pred_binary.values
)


# ============================================================
# 8. ATTACK TYPE ANALYSIS
# ============================================================

if ATTACK_TYPE_COLUMN not in analysis_df.columns:

    print("\nWARNING:")
    print(
        f"'{ATTACK_TYPE_COLUMN}' column was not found in "
        "the test dataset."
    )

else:

    print("\n")
    print("=" * 80)
    print("ATTACK TYPE ANALYSIS")
    print("=" * 80)

    attack_df = analysis_df[
        analysis_df[TARGET_COLUMN] == 1
    ].copy()

    attack_results = []

    for attack_type, group in attack_df.groupby(
        ATTACK_TYPE_COLUMN
    ):

        total = len(group)

        detected = (
            group["ids_binary_prediction"] == 1
        ).sum()

        missed = total - detected

        recall_type = (
            detected / total
            if total > 0
            else 0.0
        )

        suspicious = (
            group["ids_decision"] == "SUSPICIOUS"
        ).sum()

        attack_results.append(
            {
                "attack_type": attack_type,
                "total": total,
                "detected": detected,
                "missed": missed,
                "recall": recall_type,
                "suspicious": suspicious,
            }
        )

    attack_results_df = pd.DataFrame(
        attack_results
    )

    attack_results_df = attack_results_df.sort_values(
        by="total",
        ascending=False,
    )

    print(
        attack_results_df.to_string(
            index=False,
            formatters={
                "recall": "{:.4f}".format,
            },
        )
    )


# ============================================================
# 9. SHARED VS TEST-ONLY ATTACKS
# ============================================================

if ATTACK_TYPE_COLUMN in analysis_df.columns:

    training_df = pd.read_csv(
        Path("data/processed/nsl-kdd/train.csv")
    )

    training_attacks = set(
        training_df.loc[
            training_df[TARGET_COLUMN] == 1,
            ATTACK_TYPE_COLUMN,
        ].unique()
    )

    test_attacks = set(
        attack_df[ATTACK_TYPE_COLUMN].unique()
    )

    shared_attacks = training_attacks & test_attacks

    test_only_attacks = test_attacks - training_attacks

    print("\n")
    print("=" * 80)
    print("SHARED VS TEST-ONLY ATTACKS")
    print("=" * 80)

    print(
        f"Shared attack types:    {len(shared_attacks)}"
    )

    print(
        f"Test-only attack types: {len(test_only_attacks)}"
    )

    group_results = []

    for group_name, attack_types in [
        ("SHARED", shared_attacks),
        ("TEST_ONLY", test_only_attacks),
    ]:

        group = attack_df[
            attack_df[ATTACK_TYPE_COLUMN].isin(
                attack_types
            )
        ]

        total = len(group)

        detected = (
            group["ids_binary_prediction"] == 1
        ).sum()

        missed = total - detected

        group_recall = (
            detected / total
            if total > 0
            else 0.0
        )

        suspicious = (
            group["ids_decision"] == "SUSPICIOUS"
        ).sum()

        group_results.append(
            {
                "group": group_name,
                "samples": total,
                "detected": detected,
                "missed": missed,
                "recall": group_recall,
                "suspicious": suspicious,
            }
        )

    group_results_df = pd.DataFrame(
        group_results
    )

    print(
        group_results_df.to_string(
            index=False,
            formatters={
                "recall": "{:.4f}".format,
            },
        )
    )


# ============================================================
# 10. SUSPICIOUS DECISION ANALYSIS
# ============================================================

print("\n")
print("=" * 80)
print("SUSPICIOUS DECISION ANALYSIS")
print("=" * 80)

suspicious_mask = (
    decision == "SUSPICIOUS"
)

suspicious_count = suspicious_mask.sum()

suspicious_true_attacks = (
    suspicious_mask & (y_true == 1)
).sum()

suspicious_true_normals = (
    suspicious_mask & (y_true == 0)
).sum()


print(
    f"Total suspicious:       {suspicious_count}"
)

print(
    f"Suspicious true attacks: {suspicious_true_attacks}"
)

print(
    f"Suspicious true normals: {suspicious_true_normals}"
)

if suspicious_count > 0:

    suspicious_attack_rate = (
        suspicious_true_attacks
        / suspicious_count
    )

else:

    suspicious_attack_rate = 0.0


print(
    f"Suspicious attack rate:  {suspicious_attack_rate:.4f}"
)


# ============================================================
# 11. SAVE FINAL SUMMARY
# ============================================================

summary = pd.DataFrame(
    [
        {
            "accuracy": accuracy,
            "attack_precision": precision,
            "attack_recall": recall,
            "attack_f1": f1,
            "total_samples": len(y_true),
            "normal_samples": int((y_true == 0).sum()),
            "attack_samples": int((y_true == 1).sum()),
            "normal_decisions": int(
                (decision == "NORMAL").sum()
            ),
            "attack_decisions": int(
                (decision == "ATTACK").sum()
            ),
            "suspicious_decisions": int(
                (decision == "SUSPICIOUS").sum()
            ),
            "suspicious_true_attacks": int(
                suspicious_true_attacks
            ),
            "suspicious_true_normals": int(
                suspicious_true_normals
            ),
        }
    ]
)


OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

summary_path = (
    OUTPUT_DIR
    / "final_ids_analysis.csv"
)

summary.to_csv(
    summary_path,
    index=False,
)


# ============================================================
# 12. SAVE ATTACK TYPE RESULTS
# ============================================================

if ATTACK_TYPE_COLUMN in analysis_df.columns:

    attack_results_path = (
        OUTPUT_DIR
        / "final_ids_attack_type_analysis.csv"
    )

    attack_results_df.to_csv(
        attack_results_path,
        index=False,
    )

    print("\nSaved:")
    print(
        f"  {attack_results_path}"
    )


# ============================================================
# 13. SAVE GROUP RESULTS
# ============================================================

if ATTACK_TYPE_COLUMN in analysis_df.columns:

    group_results_path = (
        OUTPUT_DIR
        / "final_ids_group_analysis.csv"
    )

    group_results_df.to_csv(
        group_results_path,
        index=False,
    )

    print(
        f"  {group_results_path}"
    )


# ============================================================
# 14. FINAL MESSAGE
# ============================================================

print("\n")
print("=" * 80)
print("STEP 5D COMPLETE")
print("=" * 80)

print("\nFinal IDS analysis completed.")

print("\nMain result:")
print(
    f"  Accuracy:         {accuracy:.4f}"
)
print(
    f"  Attack Precision: {precision:.4f}"
)
print(
    f"  Attack Recall:    {recall:.4f}"
)
print(
    f"  Attack F1:        {f1:.4f}"
)

print("\nOutputs:")
print(
    f"  {summary_path}"
)

print("\nNext step:")
print("  Step 5E - Generate final IDS report / visualizations.")
