from pathlib import Path

import pandas as pd


TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
TEST_PATH = Path("data/processed/nsl-kdd/test.csv")


print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)


# ------------------------------------------------------------
# Get attack types
# ------------------------------------------------------------

train_attacks = set(
    train_df.loc[
        train_df["target"] == 1,
        "label",
    ].unique()
)

test_attacks = set(
    test_df.loc[
        test_df["target"] == 1,
        "label",
    ].unique()
)


# ------------------------------------------------------------
# Compare
# ------------------------------------------------------------

shared_attacks = train_attacks & test_attacks
test_only_attacks = test_attacks - train_attacks
train_only_attacks = train_attacks - test_attacks


# ------------------------------------------------------------
# Print results
# ------------------------------------------------------------

print("\nAttack type comparison")
print("=" * 70)

print(f"Training attack types: {len(train_attacks)}")
print(f"Test attack types:     {len(test_attacks)}")
print(f"Shared attack types:   {len(shared_attacks)}")


print("\nAttack types in TRAINING:")
print("=" * 70)

for attack in sorted(train_attacks):
    count = (
        train_df.loc[
            train_df["label"] == attack,
            "label",
        ].count()
    )

    print(f"{attack:20s} {count:6d}")


print("\nAttack types in TEST:")
print("=" * 70)

for attack in sorted(test_attacks):
    count = (
        test_df.loc[
            test_df["label"] == attack,
            "label",
        ].count()
    )

    print(f"{attack:20s} {count:6d}")


print("\nTEST-ONLY attack types")
print("=" * 70)

if test_only_attacks:
    for attack in sorted(test_only_attacks):
        count = (
            test_df.loc[
                test_df["label"] == attack,
                "label",
            ].count()
        )

        print(f"{attack:20s} {count:6d}")
else:
    print("None")


print("\nTRAIN-ONLY attack types")
print("=" * 70)

if train_only_attacks:
    for attack in sorted(train_only_attacks):
        count = (
            train_df.loc[
                train_df["label"] == attack,
                "label",
            ].count()
        )

        print(f"{attack:20s} {count:6d}")
else:
    print("None")