from pathlib import Path

import pandas as pd


TRAIN_PATH = Path("data/processed/nsl-kdd/train.csv")
TEST_PATH = Path("data/processed/nsl-kdd/test.csv")


# ============================================================
# Load datasets
# ============================================================

print("Loading datasets...")

train_df = pd.read_csv(TRAIN_PATH)
test_df = pd.read_csv(TEST_PATH)


# ============================================================
# Attack types we want to investigate
# ============================================================

ATTACK_TYPES = [
    "guess_passwd",
    "warezmaster",
    "processtable",
]


# ============================================================
# Numerical features
# ============================================================

NUMERICAL_FEATURES = [
    "duration",
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


# ============================================================
# 1. Compare training counts
# ============================================================

print("\nTraining examples")
print("=" * 70)

for attack in ATTACK_TYPES:

    count = (
        train_df["label"] == attack
    ).sum()

    print(f"{attack:20s}: {count}")


# ============================================================
# 2. Compare test counts
# ============================================================

print("\nTest examples")
print("=" * 70)

for attack in ATTACK_TYPES:

    count = (
        test_df["label"] == attack
    ).sum()

    print(f"{attack:20s}: {count}")


# ============================================================
# 3. Numerical feature statistics
# ============================================================

for attack in ATTACK_TYPES:

    print("\n")
    print("=" * 80)
    print(f"ATTACK TYPE: {attack}")
    print("=" * 80)

    attack_train = train_df[
        train_df["label"] == attack
    ]

    attack_test = test_df[
        test_df["label"] == attack
    ]

    print("\nTRAINING DATA")
    print("-" * 80)

    if len(attack_train) > 0:

        print(
            attack_train[
                NUMERICAL_FEATURES
            ].describe()
            .T[
                [
                    "mean",
                    "std",
                    "min",
                    "50%",
                    "max",
                ]
            ]
            .round(3)
            .to_string()
        )

    else:

        print("No training examples.")


    print("\nTEST DATA")
    print("-" * 80)

    if len(attack_test) > 0:

        print(
            attack_test[
                NUMERICAL_FEATURES
            ].describe()
            .T[
                [
                    "mean",
                    "std",
                    "min",
                    "50%",
                    "max",
                ]
            ]
            .round(3)
            .to_string()
        )

    else:

        print("No test examples.")


# ============================================================
# 4. Compare attacks against NORMAL traffic
# ============================================================

print("\n")
print("=" * 80)
print("ATTACK VS NORMAL — TRAINING DATA")
print("=" * 80)


normal_train = train_df[
    train_df["label"] == "normal"
]


for attack in ATTACK_TYPES:

    attack_train = train_df[
        train_df["label"] == attack
    ]

    print("\n")
    print(f"Attack: {attack}")
    print("-" * 80)

    comparison = pd.DataFrame(
        {
            "NORMAL_mean": normal_train[
                NUMERICAL_FEATURES
            ].mean(),

            "ATTACK_mean": attack_train[
                NUMERICAL_FEATURES
            ].mean(),
        }
    )

    comparison["difference"] = (
        comparison["ATTACK_mean"]
        - comparison["NORMAL_mean"]
    )

    comparison["abs_difference"] = (
        comparison["difference"].abs()
    )

    comparison = comparison.sort_values(
        "abs_difference",
        ascending=False,
    )

    print(
        comparison.head(10)
        .round(3)
        .to_string()
    )