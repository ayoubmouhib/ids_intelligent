from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


# ============================================================
# PATHS
# ============================================================

ANALYSIS_DIR = Path("data/analysis")
REPORT_DIR = ANALYSIS_DIR / "final_report"
FIGURE_DIR = REPORT_DIR / "figures"

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

FIGURE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# FILE PATHS
# ============================================================

FINAL_IDS_ANALYSIS = (
    ANALYSIS_DIR / "final_ids_analysis.csv"
)

FINAL_IDS_VALIDATION = (
    ANALYSIS_DIR / "final_ids_validation.csv"
)

HYBRID_THRESHOLD = (
    ANALYSIS_DIR / "hybrid_threshold_experiment.csv"
)

RF_IF_MODEL = (
    ANALYSIS_DIR / "rf_vs_if_model_comparison.csv"
)

RF_IF_GROUP = (
    ANALYSIS_DIR / "rf_vs_if_group_comparison.csv"
)

RF_IF_ATTACK = (
    ANALYSIS_DIR / "rf_vs_if_attack_comparison.csv"
)

HYBRID_GROUP = (
    ANALYSIS_DIR / "hybrid_group_comparison.csv"
)

HYBRID_ATTACK = (
    ANALYSIS_DIR / "hybrid_attack_analysis.csv"
)

ANOMALY_GROUP = (
    ANALYSIS_DIR / "anomaly_shared_attack_evaluation.csv"
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def save_figure(filename):
    """
    Save the current matplotlib figure.
    """
    path = FIGURE_DIR / filename

    plt.tight_layout()
    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight",
    )

    plt.close()

    print(f"Saved figure: {path}")


def find_column(df, candidates):
    """
    Return the first matching column from candidates.
    """
    for column in candidates:
        if column in df.columns:
            return column

    return None


# ============================================================
# START
# ============================================================

print("=" * 80)
print("STEP 5E - FINAL IDS REPORT AND VISUALIZATION")
print("=" * 80)


# ============================================================
# 1. LOAD AVAILABLE RESULTS
# ============================================================

print("\nLoading analysis results...")


final_analysis = None
validation = None
threshold_df = None
model_df = None
group_df = None
attack_df = None
hybrid_group_df = None
hybrid_attack_df = None


if FINAL_IDS_ANALYSIS.exists():

    final_analysis = pd.read_csv(
        FINAL_IDS_ANALYSIS
    )

    print(
        f"Loaded: {FINAL_IDS_ANALYSIS}"
    )

else:

    print(
        f"WARNING: Missing {FINAL_IDS_ANALYSIS}"
    )


if FINAL_IDS_VALIDATION.exists():

    validation = pd.read_csv(
        FINAL_IDS_VALIDATION
    )

    print(
        f"Loaded: {FINAL_IDS_VALIDATION}"
    )

else:

    print(
        f"WARNING: Missing {FINAL_IDS_VALIDATION}"
    )


if HYBRID_THRESHOLD.exists():

    threshold_df = pd.read_csv(
        HYBRID_THRESHOLD
    )

    print(
        f"Loaded: {HYBRID_THRESHOLD}"
    )

else:

    print(
        f"WARNING: Missing {HYBRID_THRESHOLD}"
    )


if RF_IF_MODEL.exists():

    model_df = pd.read_csv(
        RF_IF_MODEL
    )

    print(
        f"Loaded: {RF_IF_MODEL}"
    )

else:

    print(
        f"WARNING: Missing {RF_IF_MODEL}"
    )


if RF_IF_GROUP.exists():

    group_df = pd.read_csv(
        RF_IF_GROUP
    )

    print(
        f"Loaded: {RF_IF_GROUP}"
    )

else:

    print(
        f"WARNING: Missing {RF_IF_GROUP}"
    )


if RF_IF_ATTACK.exists():

    attack_df = pd.read_csv(
        RF_IF_ATTACK
    )

    print(
        f"Loaded: {RF_IF_ATTACK}"
    )

else:

    print(
        f"WARNING: Missing {RF_IF_ATTACK}"
    )


if HYBRID_GROUP.exists():

    hybrid_group_df = pd.read_csv(
        HYBRID_GROUP
    )

    print(
        f"Loaded: {HYBRID_GROUP}"
    )

else:

    print(
        f"WARNING: Missing {HYBRID_GROUP}"
    )


if HYBRID_ATTACK.exists():

    hybrid_attack_df = pd.read_csv(
        HYBRID_ATTACK
    )

    print(
        f"Loaded: {HYBRID_ATTACK}"
    )

else:

    print(
        f"WARNING: Missing {HYBRID_ATTACK}"
    )


# ============================================================
# 2. CREATE FINAL METRICS SUMMARY
# ============================================================

print("\n")
print("=" * 80)
print("FINAL PERFORMANCE SUMMARY")
print("=" * 80)


summary_rows = []


# ------------------------------------------------------------
# Random Forest
# ------------------------------------------------------------

if model_df is not None:

    rf_rows = model_df[
        model_df["model"].astype(str).str.contains(
            "Random Forest",
            case=False,
            na=False,
        )
    ]

    if not rf_rows.empty:

        row = rf_rows.iloc[0]

        summary_rows.append(
            {
                "model": "Random Forest",
                "accuracy": row["accuracy"],
                "precision": row["precision"],
                "recall": row["recall"],
                "f1": row["f1"],
            }
        )


# ------------------------------------------------------------
# Isolation Forest
# ------------------------------------------------------------

if model_df is not None:

    if_rows = model_df[
        model_df["model"].astype(str).str.contains(
            "Isolation Forest",
            case=False,
            na=False,
        )
    ]

    if not if_rows.empty:

        row = if_rows.iloc[0]

        summary_rows.append(
            {
                "model": "Isolation Forest",
                "accuracy": row["accuracy"],
                "precision": row["precision"],
                "recall": row["recall"],
                "f1": row["f1"],
            }
        )


# ------------------------------------------------------------
# Final IDS
# ------------------------------------------------------------

if final_analysis is not None:

    row = final_analysis.iloc[0]

    summary_rows.append(
        {
            "model": "Final Hybrid IDS",
            "accuracy": row["accuracy"],
            "precision": row["attack_precision"],
            "recall": row["attack_recall"],
            "f1": row["attack_f1"],
        }
    )


summary_df = pd.DataFrame(
    summary_rows
)


if not summary_df.empty:

    print(
        summary_df.to_string(
            index=False,
            formatters={
                "accuracy": "{:.4f}".format,
                "precision": "{:.4f}".format,
                "recall": "{:.4f}".format,
                "f1": "{:.4f}".format,
            },
        )
    )

    summary_path = (
        REPORT_DIR
        / "final_performance_summary.csv"
    )

    summary_df.to_csv(
        summary_path,
        index=False,
    )

    print(
        f"\nSaved: {summary_path}"
    )


# ============================================================
# 3. MODEL PERFORMANCE COMPARISON
# ============================================================

if not summary_df.empty:

    print("\nGenerating model performance chart...")

    metrics = [
        "accuracy",
        "precision",
        "recall",
        "f1",
    ]

    x = range(len(summary_df))

    width = 0.2

    plt.figure(
        figsize=(11, 6)
    )

    for index, metric in enumerate(metrics):

        values = summary_df[metric]

        positions = [
            i
            + (index - 1.5) * width
            for i in x
        ]

        plt.bar(
            positions,
            values,
            width=width,
            label=metric.upper(),
        )

    plt.xticks(
        list(x),
        summary_df["model"],
    )

    plt.ylim(
        0,
        1.05,
    )

    plt.ylabel(
        "Score"
    )

    plt.title(
        "IDS Model Performance Comparison"
    )

    plt.legend()

    save_figure(
        "01_model_performance_comparison.png"
    )


# ============================================================
# 4. PRECISION / RECALL / F1 ONLY
# ============================================================

if not summary_df.empty:

    plt.figure(
        figsize=(10, 6)
    )

    metrics = [
        "precision",
        "recall",
        "f1",
    ]

    x = range(len(summary_df))
    width = 0.25

    for index, metric in enumerate(metrics):

        positions = [
            i + (index - 1) * width
            for i in x
        ]

        plt.bar(
            positions,
            summary_df[metric],
            width=width,
            label=metric.upper(),
        )

    plt.xticks(
        list(x),
        summary_df["model"],
    )

    plt.ylim(
        0,
        1.05,
    )

    plt.ylabel(
        "Score"
    )

    plt.title(
        "Attack Detection Performance"
    )

    plt.legend()

    save_figure(
        "02_attack_detection_metrics.png"
    )


# ============================================================
# 5. HYBRID THRESHOLD EXPERIMENT
# ============================================================

if threshold_df is not None:

    print(
        "\nGenerating hybrid threshold analysis..."
    )

    threshold_column = find_column(
        threshold_df,
        [
            "if_threshold",
            "threshold",
            "IF Threshold",
        ],
    )

    f1_column = find_column(
        threshold_df,
        [
            "attack_f1",
            "f1",
            "Attack F1",
        ],
    )

    recall_column = find_column(
        threshold_df,
        [
            "attack_recall",
            "recall",
            "Attack Recall",
        ],
    )

    precision_column = find_column(
        threshold_df,
        [
            "attack_precision",
            "precision",
            "Attack Precision",
        ],
    )

    if threshold_column is not None:

        plt.figure(
            figsize=(10, 6)
        )

        if f1_column is not None:

            plt.plot(
                threshold_df[
                    threshold_column
                ],
                threshold_df[
                    f1_column
                ],
                marker="o",
                label="F1",
            )

        if recall_column is not None:

            plt.plot(
                threshold_df[
                    threshold_column
                ],
                threshold_df[
                    recall_column
                ],
                marker="o",
                label="Recall",
            )

        if precision_column is not None:

            plt.plot(
                threshold_df[
                    threshold_column
                ],
                threshold_df[
                    precision_column
                ],
                marker="o",
                label="Precision",
            )

        plt.xlabel(
            "Isolation Forest Threshold"
        )

        plt.ylabel(
            "Score"
        )

        plt.title(
            "Hybrid IDS Performance Across IF Thresholds"
        )

        plt.legend()

        save_figure(
            "03_hybrid_threshold_analysis.png"
        )


# ============================================================
# 6. SUSPICIOUS EVENTS
# ============================================================

if final_analysis is not None:

    row = final_analysis.iloc[0]

    decisions = [
        "NORMAL",
        "ATTACK",
        "SUSPICIOUS",
    ]

    counts = [
        row["normal_decisions"],
        row["attack_decisions"],
        row["suspicious_decisions"],
    ]

    plt.figure(
        figsize=(9, 6)
    )

    bars = plt.bar(
        decisions,
        counts,
    )

    plt.ylabel(
        "Number of samples"
    )

    plt.title(
        "Final IDS Decision Distribution"
    )

    for bar, value in zip(
        bars,
        counts,
    ):

        plt.text(
            bar.get_x()
            + bar.get_width() / 2,
            bar.get_height(),
            f"{int(value)}",
            ha="center",
            va="bottom",
        )

    save_figure(
        "04_final_decision_distribution.png"
    )


# ============================================================
# 7. SUSPICIOUS DECISION QUALITY
# ============================================================

if final_analysis is not None:

    row = final_analysis.iloc[0]

    suspicious_attack = int(
        row["suspicious_true_attacks"]
    )

    suspicious_normal = int(
        row["suspicious_true_normals"]
    )

    values = [
        suspicious_attack,
        suspicious_normal,
    ]

    labels = [
        "True Attack",
        "True Normal",
    ]

    plt.figure(
        figsize=(8, 6)
    )

    bars = plt.bar(
        labels,
        values,
    )

    plt.ylabel(
        "Number of suspicious events"
    )

    plt.title(
        "Ground Truth of Suspicious IDS Decisions"
    )

    for bar, value in zip(
        bars,
        values,
    ):

        plt.text(
            bar.get_x()
            + bar.get_width() / 2,
            bar.get_height(),
            f"{value}",
            ha="center",
            va="bottom",
        )

    save_figure(
        "05_suspicious_decision_quality.png"
    )


# ============================================================
# 8. SHARED VS TEST-ONLY ATTACKS
# ============================================================

if hybrid_group_df is not None:

    print(
        "\nGenerating shared vs test-only comparison..."
    )

    recall_column = find_column(
        hybrid_group_df,
        [
            "hybrid_recall",
            "recall",
        ],
    )

    f1_column = find_column(
        hybrid_group_df,
        [
            "hybrid_f1",
            "f1",
        ],
    )

    if (
        recall_column is not None
        and f1_column is not None
    ):

        plot_df = hybrid_group_df.copy()

        plt.figure(
            figsize=(9, 6)
        )

        x = range(
            len(plot_df)
        )

        width = 0.35

        plt.bar(
            [
                i - width / 2
                for i in x
            ],
            plot_df[
                recall_column
            ],
            width=width,
            label="Recall",
        )

        plt.bar(
            [
                i + width / 2
                for i in x
            ],
            plot_df[
                f1_column
            ],
            width=width,
            label="F1",
        )

        plt.xticks(
            list(x),
            plot_df["group"],
        )

        plt.ylim(
            0,
            1.05,
        )

        plt.ylabel(
            "Score"
        )

        plt.title(
            "Hybrid IDS: Shared vs Test-Only Attacks"
        )

        plt.legend()

        save_figure(
            "06_shared_vs_test_only.png"
        )


# ============================================================
# 9. ATTACK TYPE PERFORMANCE
# ============================================================

if hybrid_attack_df is not None:

    attack_recall_column = find_column(
        hybrid_attack_df,
        [
            "hybrid_recall",
            "recall",
        ],
    )

    if attack_recall_column is not None:

        plot_df = (
            hybrid_attack_df
            .copy()
            .sort_values(
                by="total",
                ascending=True,
            )
        )

        plt.figure(
            figsize=(11, 12)
        )

        plt.barh(
            plot_df["attack_type"],
            plot_df[
                attack_recall_column
            ],
        )

        plt.xlim(
            0,
            1.05,
        )

        plt.xlabel(
            "Detection Recall"
        )

        plt.ylabel(
            "Attack Type"
        )

        plt.title(
            "Hybrid IDS Recall by Attack Type"
        )

        save_figure(
            "07_attack_type_recall.png"
        )


# ============================================================
# 10. RF VS IF ATTACK TYPE COMPARISON
# ============================================================

if attack_df is not None:

    rf_recall = find_column(
        attack_df,
        [
            "rf_recall",
        ],
    )

    if_recall = find_column(
        attack_df,
        [
            "if_recall",
        ],
    )

    if (
        rf_recall is not None
        and if_recall is not None
    ):

        plot_df = (
            attack_df
            .copy()
            .sort_values(
                by="total",
                ascending=True,
            )
        )

        plt.figure(
            figsize=(12, 14)
        )

        y = range(
            len(plot_df)
        )

        width = 0.35

        plt.barh(
            [
                i - width / 2
                for i in y
            ],
            plot_df[rf_recall],
            height=width,
            label="Random Forest",
        )

        plt.barh(
            [
                i + width / 2
                for i in y
            ],
            plot_df[if_recall],
            height=width,
            label="Isolation Forest",
        )

        plt.yticks(
            list(y),
            plot_df["attack_type"],
        )

        plt.xlim(
            0,
            1.05,
        )

        plt.xlabel(
            "Recall"
        )

        plt.ylabel(
            "Attack Type"
        )

        plt.title(
            "Random Forest vs Isolation Forest by Attack Type"
        )

        plt.legend()

        save_figure(
            "08_rf_vs_if_attack_types.png"
        )


# ============================================================
# 11. CREATE TEXT REPORT
# ============================================================

print("\nGenerating final text report...")


report_path = (
    REPORT_DIR
    / "FINAL_IDS_REPORT.txt"
)


with open(
    report_path,
    "w",
    encoding="utf-8",
) as report:

    report.write(
        "=" * 80
        + "\n"
    )

    report.write(
        "FINAL INTELLIGENT INTRUSION DETECTION SYSTEM REPORT\n"
    )

    report.write(
        "=" * 80
        + "\n\n"
    )

    report.write(
        "1. FINAL IDS PERFORMANCE\n"
    )

    report.write(
        "-" * 80
        + "\n"
    )

    if final_analysis is not None:

        row = final_analysis.iloc[0]

        report.write(
            f"Accuracy:         "
            f"{row['accuracy']:.4f}\n"
        )

        report.write(
            f"Attack Precision: "
            f"{row['attack_precision']:.4f}\n"
        )

        report.write(
            f"Attack Recall:    "
            f"{row['attack_recall']:.4f}\n"
        )

        report.write(
            f"Attack F1:        "
            f"{row['attack_f1']:.4f}\n"
        )

        report.write(
            f"Total samples:    "
            f"{int(row['total_samples'])}\n"
        )

        report.write(
            f"Normal samples:   "
            f"{int(row['normal_samples'])}\n"
        )

        report.write(
            f"Attack samples:   "
            f"{int(row['attack_samples'])}\n"
        )

    report.write(
        "\n2. FINAL IDS DECISIONS\n"
    )

    report.write(
        "-" * 80
        + "\n"
    )

    if final_analysis is not None:

        report.write(
            f"NORMAL:      "
            f"{int(row['normal_decisions'])}\n"
        )

        report.write(
            f"ATTACK:      "
            f"{int(row['attack_decisions'])}\n"
        )

        report.write(
            f"SUSPICIOUS:  "
            f"{int(row['suspicious_decisions'])}\n"
        )

        report.write(
            f"\nSuspicious true attacks: "
            f"{int(row['suspicious_true_attacks'])}\n"
        )

        report.write(
            f"Suspicious true normals: "
            f"{int(row['suspicious_true_normals'])}\n"
        )

    report.write(
        "\n3. ARCHITECTURE\n"
    )

    report.write(
        "-" * 80
        + "\n"
    )

    report.write(
        "Random Forest provides the primary supervised "
        "attack classification.\n"
    )

    report.write(
        "Isolation Forest provides a complementary "
        "anomaly signal learned from normal traffic.\n"
    )

    report.write(
        "\nDecision policy:\n"
    )

    report.write(
        "  RF ATTACK + IF anything  -> ATTACK\n"
    )

    report.write(
        "  RF NORMAL + IF ANOMALY   -> SUSPICIOUS\n"
    )

    report.write(
        "  RF NORMAL + IF NORMAL    -> NORMAL\n"
    )

    report.write(
        "\n4. IMPORTANT INTERPRETATION\n"
    )

    report.write(
        "-" * 80
        + "\n"
    )

    report.write(
        "The Random Forest is the primary detection model.\n"
    )

    report.write(
        "The Isolation Forest acts as a complementary "
        "anomaly detector.\n"
    )

    report.write(
        "Suspicious decisions represent traffic for which "
        "the supervised and anomaly signals disagree.\n"
    )

    report.write(
        "\n5. GENERATED FIGURES\n"
    )

    report.write(
        "-" * 80
        + "\n"
    )

    for figure in sorted(
        FIGURE_DIR.glob("*.png")
    ):

        report.write(
            f"{figure.name}\n"
        )


print(
    f"Saved report: {report_path}"
)


# ============================================================
# 12. FINAL SUMMARY
# ============================================================

print("\n")
print("=" * 80)
print("STEP 5E COMPLETE")
print("=" * 80)

print("\nFinal report directory:")
print(
    f"  {REPORT_DIR}"
)

print("\nFigures:")
for figure in sorted(
    FIGURE_DIR.glob("*.png")
):
    print(
        f"  {figure}"
    )

print("\nReport:")
print(
    f"  {report_path}"
)

print("\nStep 5E is complete.")
