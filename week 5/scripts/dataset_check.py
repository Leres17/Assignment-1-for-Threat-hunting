from pathlib import Path
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
TYPES_DIR = BASE_DIR / "fil_types"


print("=" * 70)
print("CIC-DDoS2019 DATASET CHECK")
print("=" * 70)

if not TYPES_DIR.exists():
    print(f"\nERROR: folder not found:")
    print(TYPES_DIR)
    exit()

files = sorted(TYPES_DIR.glob("*/*.csv"))

if not files:
    print("\nNo CSV files found in fil_types/")
    exit()

total_rows = 0

for file in files:

    try:
        df = pd.read_csv(
            file,
            usecols=["Label", "Protocol"],
            low_memory=False
        )

        rows = len(df)
        total_rows += rows

        labels = df["Label"].value_counts().to_dict()
        protocols = df["Protocol"].value_counts().to_dict()

        print()
        print("-" * 70)
        print(f"FILE: {file.relative_to(BASE_DIR)}")
        print(f"ROWS: {rows:,}")

        print("\nLabels:")
        for label, count in labels.items():
            print(f"  {label}: {count:,}")

        print("\nProtocols:")
        for protocol, count in protocols.items():
            print(f"  {protocol}: {count:,}")

    except Exception as error:
        print()
        print(f"ERROR: {file}")
        print(error)


print()
print("=" * 70)
print(f"TOTAL ROWS: {total_rows:,}")
print("=" * 70)