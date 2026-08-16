from pathlib import Path

import pandas as pd


TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
TEST_PATH = Path("data/processed/nsl-kdd/test.csv")

ATTACK_TYPE = "guess_passwd"

FEATURES = [
    "num_failed_logins",
    "rerror_rate",
    "srv_rerror_rate",
    "src_bytes",
    "dst_bytes",
    "duration",
]


print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)

train_attack = train_df[train_df["label"] == ATTACK_TYPE]
test_attack = test_df[test_df["label"] == ATTACK_TYPE]

print()
print("=" * 80)
print(f"Attack type: {ATTACK_TYPE}")
print("=" * 80)

print(f"Training samples: {len(train_attack)}")
print(f"Test samples:     {len(test_attack)}")


for feature in FEATURES:

    train_mean = train_attack[feature].mean()
    test_mean = test_attack[feature].mean()

    train_median = train_attack[feature].median()
    test_median = test_attack[feature].median()

    print()
    print(f"Feature: {feature}")
    print("-" * 80)

    print(f"Training mean:   {train_mean:.4f}")
    print(f"Test mean:       {test_mean:.4f}")

    print(f"Training median: {train_median:.4f}")
    print(f"Test median:     {test_median:.4f}")


print()
print("Distribution comparison complete.")
