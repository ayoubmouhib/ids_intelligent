from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


TEST_PATH = Path("data/processed/nsl-kdd/test.csv")


# ============================================================
# Load test data
# ============================================================

print("Loading test dataset...")

df = pd.read_csv(TEST_PATH)


# ============================================================
# Attacks we want to investigate
# ============================================================

ATTACK_TYPES = [
    "guess_passwd",
    "warezmaster",
    "processtable",
]


# ============================================================
# Features selected from our previous analysis
# ============================================================

FEATURES = {
    "guess_passwd": [
        "num_failed_logins",
        "rerror_rate",
        "srv_rerror_rate",
        "src_bytes",
        "dst_bytes",
        "duration",
    ],

    "warezmaster": [
        "dst_bytes",
        "src_bytes",
        "duration",
        "num_file_creations",
        "hot",
        "dst_host_same_src_port_rate",
    ],

    "processtable": [
        "src_bytes",
        "dst_bytes",
        "duration",
        "count",
        "srv_count",
        "dst_host_srv_count",
    ],
}


# ============================================================
# Create output directory
# ============================================================

OUTPUT_DIR = Path("ml/analysis/plots")

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# Create plots
# ============================================================

for attack in ATTACK_TYPES:

    attack_df = df[
        df["label"] == attack
    ]

    normal_df = df[
        df["label"] == "normal"
    ]

    print()
    print("=" * 70)
    print(f"Attack: {attack}")
    print("=" * 70)

    print(f"Normal examples: {len(normal_df)}")
    print(f"Attack examples: {len(attack_df)}")

    for feature in FEATURES[attack]:

        print(f"Creating plot: {feature}")

        plt.figure(figsize=(10, 6))

        plt.hist(
            normal_df[feature],
            bins=50,
            alpha=0.6,
            label="NORMAL",
        )

        plt.hist(
            attack_df[feature],
            bins=50,
            alpha=0.6,
            label=attack,
        )

        plt.xlabel(feature)
        plt.ylabel("Frequency")

        plt.title(
            f"{feature}: NORMAL vs {attack}"
        )

        plt.legend()

        plt.tight_layout()

        output_path = (
            OUTPUT_DIR
            / f"{attack}_{feature}.png"
        )

        plt.savefig(output_path)

        plt.close()

    print(
        f"Saved plots to: {OUTPUT_DIR}"
    )


print()
print("Visualization complete.")