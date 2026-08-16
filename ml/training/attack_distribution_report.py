from pathlib import Path

import pandas as pd


TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
TEST_PATH = Path("data/processed/nsl-kdd/test.csv")


print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)


# ---------------------------------------------------------
# 1. Get attack counts
# ---------------------------------------------------------

train_attacks = (
    train_df[train_df["label"] != "normal"]["label"]
    .value_counts()
    .rename("train_count")
)

test_attacks = (
    test_df[test_df["label"] != "normal"]["label"]
    .value_counts()
    .rename("test_count")
)


# ---------------------------------------------------------
# 2. Combine training and test attack types
# ---------------------------------------------------------

comparison = pd.concat(
    [train_attacks, test_attacks],
    axis=1,
).fillna(0)


comparison["train_count"] = comparison["train_count"].astype(int)
comparison["test_count"] = comparison["test_count"].astype(int)


# ---------------------------------------------------------
# 3. Determine whether attack appeared during training
# ---------------------------------------------------------

comparison["seen_in_training"] = comparison["train_count"] > 0

comparison["test_only"] = (
    (comparison["train_count"] == 0)
    & (comparison["test_count"] > 0)
)


# ---------------------------------------------------------
# 4. Calculate percentages
# ---------------------------------------------------------

total_train_attacks = train_attacks.sum()
total_test_attacks = test_attacks.sum()

comparison["train_percentage"] = (
    comparison["train_count"]
    / total_train_attacks
    * 100
)

comparison["test_percentage"] = (
    comparison["test_count"]
    / total_test_attacks
    * 100
)


# ---------------------------------------------------------
# 5. Sort by test count
# ---------------------------------------------------------

comparison = comparison.sort_values(
    "test_count",
    ascending=False,
)


# ---------------------------------------------------------
# 6. Display report
# ---------------------------------------------------------

print()
print("=" * 100)
print("FULL ATTACK DISTRIBUTION REPORT")
print("=" * 100)

print()
print(f"Total training attacks: {total_train_attacks:,}")
print(f"Total test attacks:     {total_test_attacks:,}")

print()
print(
    comparison[
        [
            "train_count",
            "test_count",
            "train_percentage",
            "test_percentage",
            "seen_in_training",
            "test_only",
        ]
    ].to_string()
)


# ---------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------

test_only = comparison[comparison["test_only"]]

shared = comparison[
    (comparison["train_count"] > 0)
    & (comparison["test_count"] > 0)
]

train_only = comparison[
    (comparison["train_count"] > 0)
    & (comparison["test_count"] == 0)
]


print()
print("=" * 100)
print("SUMMARY")
print("=" * 100)

print()
print(f"Total attack types:       {len(comparison)}")
print(f"Shared attack types:      {len(shared)}")
print(f"Test-only attack types:   {len(test_only)}")
print(f"Train-only attack types:  {len(train_only)}")


print()
print("TEST-ONLY ATTACK TYPES")
print("-" * 100)

if len(test_only) == 0:
    print("None")
else:
    print(
        test_only[
            ["test_count", "test_percentage"]
        ].to_string()
    )


print()
print("TRAIN-ONLY ATTACK TYPES")
print("-" * 100)

if len(train_only) == 0:
    print("None")
else:
    print(
        train_only[
            ["train_count", "train_percentage"]
        ].to_string()
    )


print()
print("SHARED ATTACK TYPES")
print("-" * 100)

print(
    shared[
        [
            "train_count",
            "test_count",
            "train_percentage",
            "test_percentage",
        ]
    ].to_string()
)


# ---------------------------------------------------------
# 8. Save report
# ---------------------------------------------------------

output_dir = Path("data/analysis")
output_dir.mkdir(parents=True, exist_ok=True)

output_path = output_dir / "attack_distribution_report.csv"

comparison.to_csv(output_path)

print()
print(f"Report saved to: {output_path}")
