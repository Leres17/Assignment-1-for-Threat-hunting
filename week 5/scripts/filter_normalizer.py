from pathlib import Path
import pandas as pd
import re


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

RAW_DIR = BASE_DIR / "raw"
FILTERED_DIR = BASE_DIR / "filtered"
TYPES_DIR = BASE_DIR / "fil_types"

# Number of CSV rows processed at once.
# Keeps RAM usage under control for large CIC-DDoS2019 files.
CHUNK_SIZE = 50_000


# ============================================================
# COLUMNS
# ============================================================

# Columns useful for our threat hunting task.
# We do not need all ~80 CIC-DDoS2019 fields.

USEFUL_COLUMNS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",

    "Flow Duration",

    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",

    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",

    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "PSH Flag Count",

    "Packet Length Mean",
    "Packet Length Std",

    "Inbound",

    "Label",
]


# ============================================================
# HELPERS
# ============================================================

def clean_column_names(df):
    """
    Removes unnecessary spaces around column names.
    CIC-DDoS2019 contains inconsistent spacing in headers.
    """
    df.columns = [
        str(column).strip()
        for column in df.columns
    ]

    return df


def normalize_ip(value):
    """
    Normalizes IP values.

    Important:
    We DO NOT remove private IP addresses.
    CIC-DDoS2019 is a laboratory dataset and private
    addresses are meaningful network telemetry.
    """

    if pd.isna(value):
        return value

    value = str(value).strip()

    return value


def normalize_label(value):
    """
    Normalizes attack labels.

    Example:
        ' Syn ' -> 'Syn'
        ' UDP-lag ' -> 'UDP-lag'
    """

    if pd.isna(value):
        return value

    value = str(value).strip()

    return value


def normalize_protocol(value):
    """
    Converts protocol values into integers where possible.

    CIC-DDoS2019 normally uses:
        6  = TCP
        17 = UDP
    """

    if pd.isna(value):
        return value

    try:
        return int(float(value))
    except (ValueError, TypeError):
        return value


def normalize_numeric_columns(df):
    """
    Converts important numeric fields to numeric values.

    Invalid values become NaN instead of crashing the pipeline.
    """

    numeric_columns = [
        "Source Port",
        "Destination Port",
        "Protocol",

        "Flow Duration",

        "Total Fwd Packets",
        "Total Backward Packets",

        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",

        "Flow Bytes/s",
        "Flow Packets/s",
        "Fwd Packets/s",
        "Bwd Packets/s",

        "SYN Flag Count",
        "ACK Flag Count",
        "RST Flag Count",
        "PSH Flag Count",

        "Packet Length Mean",
        "Packet Length Std",

        "Inbound",
    ]

    for column in numeric_columns:
        if column in df.columns:
            df[column] = pd.to_numeric(
                df[column],
                errors="coerce"
            )

    return df


# ============================================================
# FILTERING
# ============================================================

def filter_data(df):
    """
    Performs basic data filtering.

    Removes:
    - rows without source IP
    - rows without destination IP
    - rows without protocol
    - rows without label

    Also removes exact duplicate flows inside the chunk.
    """

    required_columns = [
        "Source IP",
        "Destination IP",
        "Protocol",
        "Label",
    ]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(
                f"Required column is missing: {column}"
            )

    # Remove rows without important telemetry
    df = df.dropna(
        subset=required_columns
    )

    # Remove empty IP strings
    df = df[
        (df["Source IP"].astype(str).str.strip() != "") &
        (df["Destination IP"].astype(str).str.strip() != "")
    ]

    # Remove duplicate rows
    df = df.drop_duplicates()

    return df


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_data(df):
    """
    Normalizes values while keeping the original
    CIC-DDoS2019 structure useful for threat hunting.
    """

    # IP addresses
    df["Source IP"] = df["Source IP"].apply(
        normalize_ip
    )

    df["Destination IP"] = df["Destination IP"].apply(
        normalize_ip
    )

    # Labels
    df["Label"] = df["Label"].apply(
        normalize_label
    )

    # Protocol
    df["Protocol"] = df["Protocol"].apply(
        normalize_protocol
    )

    # Numeric fields
    df = normalize_numeric_columns(df)

    return df


# ============================================================
# COLUMN SELECTION
# ============================================================

def select_useful_columns(df):
    """
    Keeps only columns needed for our threat hunting work.

    Missing columns are ignored so the script does not crash
    if a CIC CSV has a slightly different structure.
    """

    available_columns = [
        column
        for column in USEFUL_COLUMNS
        if column in df.columns
    ]

    return df[available_columns]


# ============================================================
# OUTPUT
# ============================================================

def append_dataframe(df, output_file):
    """
    Appends a dataframe to CSV.

    Header is written only when the file does not exist yet.
    """

    write_header = not output_file.exists()

    df.to_csv(
        output_file,
        mode="a",
        header=write_header,
        index=False,
        encoding="utf-8"
    )


# ============================================================
# PROCESS ONE FILE
# ============================================================

def process_file(input_file):
    """
    Processes one raw CIC-DDoS2019 CSV file.
    """

    print()
    print("=" * 70)
    print(f"PROCESSING: {input_file.name}")
    print("=" * 70)

    base_name = input_file.stem

    filtered_file = FILTERED_DIR / (
        f"{base_name}_filtered.csv"
    )

    normalized_file = FILTERED_DIR / (
        f"{base_name}_normalized.csv"
    )

    # Remove old outputs if they exist.
    # This prevents duplicate data if the script is rerun
    # after a previous failed processing attempt.
    if filtered_file.exists():
        filtered_file.unlink()

    if normalized_file.exists():
        normalized_file.unlink()

    # Statistics
    total_rows = 0
    filtered_rows = 0
    normalized_rows = 0

    type_files = {}

    try:

        # ----------------------------------------------------
        # READ CSV IN CHUNKS
        # ----------------------------------------------------

        for chunk_number, chunk in enumerate(
            pd.read_csv(
                input_file,
                chunksize=CHUNK_SIZE,
                low_memory=False
            ),
            start=1
        ):

            print(
                f"  Chunk {chunk_number}: "
                f"{len(chunk):,} rows"
            )

            total_rows += len(chunk)

            # ------------------------------------------------
            # CLEAN COLUMN NAMES
            # ------------------------------------------------

            chunk = clean_column_names(chunk)

            # ------------------------------------------------
            # REMOVE UNNAMED INDEX
            # ------------------------------------------------

            unnamed_columns = [
                column
                for column in chunk.columns
                if column.lower().startswith("unnamed:")
            ]

            if unnamed_columns:
                chunk = chunk.drop(
                    columns=unnamed_columns
                )

            # ------------------------------------------------
            # SELECT IMPORTANT COLUMNS
            # ------------------------------------------------

            chunk = select_useful_columns(chunk)

            # ------------------------------------------------
            # FILTER
            # ------------------------------------------------

            chunk = filter_data(chunk)

            filtered_rows += len(chunk)

            if chunk.empty:
                continue

            # Save filtered data
            append_dataframe(
                chunk,
                filtered_file
            )

            # ------------------------------------------------
            # NORMALIZATION
            # ------------------------------------------------

            chunk = normalize_data(chunk)

            normalized_rows += len(chunk)

            # Save normalized data
            append_dataframe(
                chunk,
                normalized_file
            )

            # ------------------------------------------------
            # SPLIT BY LABEL
            # ------------------------------------------------

            for label, label_data in chunk.groupby(
                "Label",
                dropna=False
            ):

                if pd.isna(label):
                    label_name = "UNKNOWN"
                else:
                    label_name = str(label).strip()

                # Make label safe for filesystem
                label_name = re.sub(
                    r'[<>:"/\\|?*]',
                    "_",
                    label_name
                )

                # Create folder
                label_dir = TYPES_DIR / label_name
                label_dir.mkdir(
                    parents=True,
                    exist_ok=True
                )

                type_file = label_dir / (
                    f"{base_name}_{label_name}.csv"
                )

                append_dataframe(
                    label_data,
                    type_file
                )

                type_files[label_name] = (
                    type_files.get(label_name, 0)
                    + len(label_data)
                )

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        print()
        print("PROCESSING COMPLETED")
        print("-" * 70)

        print(
            f"Raw rows:          {total_rows:,}"
        )

        print(
            f"Filtered rows:     {filtered_rows:,}"
        )

        print(
            f"Normalized rows:   {normalized_rows:,}"
        )

        print()
        print("Labels:")

        for label, count in sorted(
            type_files.items()
        ):
            print(
                f"  {label}: {count:,}"
            )

        print()
        print("Created:")

        print(
            f"  {filtered_file}"
        )

        print(
            f"  {normalized_file}"
        )

        # ----------------------------------------------------
        # MARK RAW FILE AS PROCESSED
        # ----------------------------------------------------

        processed_file = (
            input_file.parent
            / f"-f-{input_file.name}"
        )

        input_file.rename(
            processed_file
        )

        print()
        print(
            f"Raw file marked as processed:"
        )

        print(
            f"  {processed_file.name}"
        )

        return True

    except Exception as error:

        print()
        print("ERROR WHILE PROCESSING FILE")
        print("-" * 70)
        print(error)

        print()
        print(
            "The raw file was NOT renamed with '-f-'."
        )

        print(
            "It can be processed again after fixing the problem."
        )

        return False


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("CIC-DDoS2019 FILTER + NORMALIZATION PIPELINE")
    print("=" * 70)

    # --------------------------------------------------------
    # CREATE DIRECTORIES
    # --------------------------------------------------------

    RAW_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    FILTERED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    TYPES_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # FIND RAW CSV FILES
    # --------------------------------------------------------

    raw_files = sorted(
        RAW_DIR.glob("*.csv")
    )

    # Ignore already processed files
    raw_files = [
        file
        for file in raw_files
        if not file.name.startswith("-f-")
    ]

    # --------------------------------------------------------
    # NOTHING TO PROCESS
    # --------------------------------------------------------

    if not raw_files:

        print()
        print("No new CSV files found in raw/")
        print()
        print(
            "Put CIC-DDoS2019 CSV files into:"
        )

        print(
            f"  {RAW_DIR}"
        )

        print()
        return

    # --------------------------------------------------------
    # PROCESS FILES
    # --------------------------------------------------------

    print()
    print(
        f"New files found: {len(raw_files)}"
    )

    for file in raw_files:

        success = process_file(file)

        if not success:
            print()
            print(
                f"FAILED: {file.name}"
            )

    # --------------------------------------------------------
    # FINISHED
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("PIPELINE FINISHED")
    print("=" * 70)

    print()
    print("Directories:")

    print(
        f"  Raw:       {RAW_DIR}"
    )

    print(
        f"  Filtered:  {FILTERED_DIR}"
    )

    print(
        f"  By type:   {TYPES_DIR}"
    )

    print()


if __name__ == "__main__":
    main()