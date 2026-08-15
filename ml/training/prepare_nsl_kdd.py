from pathlib import Path

import pandas as pd


# --------------------------------------------------
# Paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "nsl-kdd"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed" / "nsl-kdd"


TRAIN_FILE = RAW_DIR / "KDDTrain+.txt"
TEST_FILE = RAW_DIR / "KDDTest+.txt"

TRAIN_OUTPUT = PROCESSED_DIR / "train.csv"
TEST_OUTPUT = PROCESSED_DIR / "test.csv"


# --------------------------------------------------
# NSL-KDD column names
# --------------------------------------------------

COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
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
    "label",
    "difficulty",
]


# --------------------------------------------------
# Load dataset
# --------------------------------------------------

def load_dataset(path: Path) -> pd.DataFrame:
    """Load an NSL-KDD file."""

    df = pd.read_csv(
        path,
        header=None,
        names=COLUMNS,
    )

    return df


# --------------------------------------------------
# Process dataset
# --------------------------------------------------

def process_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare NSL-KDD for the first binary IDS task."""

    categorical_columns = [
    "protocol_type",
    "service",
    "flag",
    "label",
]

    for column in categorical_columns:
        df[column] = df[column].str.strip()

    # Create binary target:
    # normal -> NORMAL
    # everything else -> ATTACK
    df["target"] = (df["label"] != "normal").astype(int)

    # Remove dataset metadata that should not be used
    # as a model feature.
    df = df.drop(columns=["difficulty"])

    return df


# --------------------------------------------------
# Validation
# --------------------------------------------------

def validate_dataset(df: pd.DataFrame, name: str) -> None:
    """Validate the processed dataset."""

    print(f"\n--- {name} ---")

    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")

    print("\nMissing values:")
    print(df.isnull().sum().sum())

    print("\nTarget distribution:")
    print(df["target"].value_counts())

    print("\nTarget meaning:")
    print("0 = NORMAL")
    print("1 = ATTACK")


# --------------------------------------------------
# Main
# --------------------------------------------------

def main() -> None:

    print("Loading NSL-KDD datasets...")

    train_df = load_dataset(TRAIN_FILE)
    test_df = load_dataset(TEST_FILE)

    print(f"Raw train shape: {train_df.shape}")
    print(f"Raw test shape:  {test_df.shape}")

    print("\nProcessing datasets...")

    train_df = process_dataset(train_df)
    test_df = process_dataset(test_df)

    validate_dataset(train_df, "Processed Train")
    validate_dataset(test_df, "Processed Test")

    # Create output directory
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    # Save processed datasets
    train_df.to_csv(TRAIN_OUTPUT, index=False)
    test_df.to_csv(TEST_OUTPUT, index=False)

    print("\nProcessed datasets saved:")

    print(TRAIN_OUTPUT)
    print(TEST_OUTPUT)


if __name__ == "__main__":
    main()