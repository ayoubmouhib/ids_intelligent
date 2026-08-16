from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")

ATTACK_TYPE = "guess_passwd"

FEATURES = [
    "num_failed_logins",
    "rerror_rate",
    "srv_rerror_rate",
    "src_bytes",
    "dst_bytes",
    "duration",
]


print("Loading training dataset...")

df = pd.read_csv(TRAIN_PATH)

normal = df[df["label"] == "normal"]
attack = df[df["label"] == ATTACK_TYPE]

print(f"NORMAL samples:       {len(normal)}")
print(f"{ATTACK_TYPE} samples: {len(attack)}")


output_dir = Path("data/analysis")
output_dir.mkdir(parents=True, exist_ok=True)


for feature in FEATURES:

    print(f"\nAnalyzing: {feature}")

    normal_values = normal[feature]
    attack_values = attack[feature]

    print(f"NORMAL mean:       {normal_values.mean():.4f}")
    print(f"{ATTACK_TYPE} mean: {attack_values.mean():.4f}")

    print(f"NORMAL median:       {normal_values.median():.4f}")
    print(f"{ATTACK_TYPE} median: {attack_values.median():.4f}")

    plt.figure(figsize=(10, 6))

    plt.boxplot(
        [
            normal_values,
            attack_values,
        ],
        tick_labels=[
            "NORMAL",
            ATTACK_TYPE,
        ],
        showfliers=False,
    )

    plt.title(f"{feature}: NORMAL vs {ATTACK_TYPE}")
    plt.ylabel(feature)
    plt.grid(axis="y", alpha=0.3)

    output_path = output_dir / f"{ATTACK_TYPE}_{feature}_boxplot.png"

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

    print(f"Saved: {output_path}")


print("\nAnalysis complete.")
