from pathlib import Path

import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder


# --------------------------------------------------
# Paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed" / "nsl-kdd"

TRAIN_FILE = DATA_DIR / "train.csv"
TEST_FILE = DATA_DIR / "test.csv"


# --------------------------------------------------
# Load data
# --------------------------------------------------

train_df = pd.read_csv(TRAIN_FILE)
test_df = pd.read_csv(TEST_FILE)


# --------------------------------------------------
# Separate features (X) and target (y)
# --------------------------------------------------

X_train = train_df.drop(columns=["label", "target"])
y_train = train_df["target"]

X_test = test_df.drop(columns=["label", "target"])
y_test = test_df["target"]


# --------------------------------------------------
# Feature types
# --------------------------------------------------

categorical_features = [
    "protocol_type",
    "service",
    "flag",
]

numerical_features = [
    column
    for column in X_train.columns
    if column not in categorical_features
]


# --------------------------------------------------
# Preprocessor
# --------------------------------------------------

preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore",
                sparse_output=True,
            ),
            categorical_features,
        ),
    ],
    remainder="passthrough",
)


# --------------------------------------------------
# Fit on training data
# --------------------------------------------------

X_train_transformed = preprocessor.fit_transform(X_train)


# --------------------------------------------------
# Transform test data
# --------------------------------------------------

X_test_transformed = preprocessor.transform(X_test)


# --------------------------------------------------
# Information
# --------------------------------------------------

print("Original training shape:")
print(X_train.shape)

print("\nOriginal test shape:")
print(X_test.shape)

print("\nTransformed training shape:")
print(X_train_transformed.shape)

print("\nTransformed test shape:")
print(X_test_transformed.shape)

print("\nTarget training shape:")
print(y_train.shape)

print("\nTarget test shape:")
print(y_test.shape)

print("\nNumber of learned output features:")
print(len(preprocessor.get_feature_names_out()))