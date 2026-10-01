from pathlib import Path
import re
import ipaddress


# FILES


# Always use the folder where this Python script is located.
BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "raw_ioc.txt"
FILTERED_FILE = BASE_DIR / "filtered_ioc.txt"
NORMALIZED_FILE = BASE_DIR / "normalized_ioc.txt"



# PARSING


def parse_line(line):
    """
    Convert:
        IP=1.2.3.4 | Domain=example.com | URL=https://example.com

    into:
        {
            "IP": "1.2.3.4",
            "Domain": "example.com",
            "URL": "https://example.com"
        }

    Missing fields are simply ignored.
    """

    data = {}

    parts = line.split("|")

    for part in parts:
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)

        key = key.strip()
        value = value.strip()

        data[key] = value

    return data



# VALIDATION


def is_valid_ip(value):
    """
    Check whether an IP address is valid.

    Private, loopback and link-local addresses
    are removed because they are not useful as
    public DDoS threat intelligence indicators.
    """

    if not value:
        return False

    try:
        ip = ipaddress.ip_address(value)

        if ip.is_private:
            return False

        if ip.is_loopback:
            return False

        if ip.is_link_local:
            return False

        return True

    except ValueError:
        return False


def is_valid_domain(value):
    """
    Basic domain validation.
    """

    if not value:
        return False

    value = value.strip()

    pattern = (
        r"^(?=.{1,253}$)"
        r"([a-zA-Z0-9]"
        r"([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )

    return bool(re.match(pattern, value))


def is_valid_url(value):
    """
    Basic HTTP/HTTPS URL validation.
    """

    if not value:
        return False

    value = value.strip()

    pattern = r"^https?://[^\s]+$"

    return bool(re.match(pattern, value, re.IGNORECASE))



# FILTERING


def filter_data(lines):
    """
    Filtering stage.

    Removes:
    - empty lines
    - rows without a valid IP, domain or URL
    - duplicate rows

    A row is kept if it contains at least
    one valid IOC.
    """

    filtered = []
    seen = set()

    for line in lines:

        original_line = line.strip()

        # Ignore empty lines
        if not original_line:
            continue

        data = parse_line(original_line)

        ip = data.get("IP", "")
        domain = data.get("Domain", "")
        url = data.get("URL", "")

        # Check whether at least one IOC is valid
        valid_ioc = False

        if is_valid_ip(ip):
            valid_ioc = True

        if is_valid_domain(domain):
            valid_ioc = True

        if is_valid_url(url):
            valid_ioc = True

        # Remove rows containing no valid IOC
        if not valid_ioc:
            continue

        # Used only for duplicate detection.
        # Original formatting is still preserved.
        duplicate_key = original_line.lower()

        if duplicate_key in seen:
            continue

        seen.add(duplicate_key)

        # IMPORTANT:
        # Filtering does not normalize the data.
        # The original line is saved.
        filtered.append(original_line)

    return filtered



# NORMALIZATION


def normalize_url(url):
    """
    Normalize a URL without changing the path unnecessarily.

    Example:
        HTTPS://Example.COM/Test
    becomes:
        https://example.com/Test
    """

    if not url:
        return ""

    url = url.strip()

    match = re.match(
        r"^(https?://)([^/]+)(.*)$",
        url,
        re.IGNORECASE
    )

    if not match:
        return url.lower()

    scheme = match.group(1).lower()
    host = match.group(2).lower()
    path = match.group(3)

    return scheme + host + path


def normalize_data(lines):
    """
    Normalization stage.

    Standardizes:
    - spaces
    - domain to lowercase
    - URL scheme and hostname to lowercase
    - Type to lowercase
    - Source spacing
    - Date spacing

    Missing fields are preserved as empty values.
    """

    normalized = []

    for line in lines:

        data = parse_line(line)

        # Missing fields become empty strings.
        ip = data.get("IP", "").strip()
        domain = data.get("Domain", "").strip().lower()
        url = data.get("URL", "").strip()
        ioc_type = data.get("Type", "").strip().lower()
        source = data.get("Source", "").strip()
        date = data.get("Date", "").strip()

        # Normalize URL
        url = normalize_url(url)

        # Create one standardized format
        output = (
            f"IP={ip} | "
            f"Domain={domain} | "
            f"URL={url} | "
            f"Type={ioc_type} | "
            f"Source={source} | "
            f"Date={date}"
        )

        normalized.append(output)

    return normalized



# MAIN 


if not INPUT_FILE.exists():

    print("ERROR: raw_ioc.txt was not found.")
    print()
    print("Python is looking for the file here:")
    print(INPUT_FILE)
    print()
    print("Put raw_ioc.txt into the same folder as filter_normalizer.py")

    exit()



# Read raw data


with open(INPUT_FILE, "r", encoding="utf-8") as file:
    raw_data = file.readlines()



# Filtering


filtered_data = filter_data(raw_data)

with open(FILTERED_FILE, "w", encoding="utf-8") as file:

    for line in filtered_data:
        file.write(line + "\n")



# Normalization


normalized_data = normalize_data(filtered_data)

with open(NORMALIZED_FILE, "w", encoding="utf-8") as file:

    for line in normalized_data:
        file.write(line + "\n")



# RESULTS


print("=" * 55)
print("IOC PROCESSING COMPLETED")
print("=" * 55)

print(f"Raw indicators:       {len(raw_data)}")
print(f"After filtering:      {len(filtered_data)}")
print(f"After normalization:  {len(normalized_data)}")

print()
print("Files created:")

print(f"1. {FILTERED_FILE}")
print(f"2. {NORMALIZED_FILE}")

print()
print("Pipeline:")
print("raw_ioc.txt")
print("      ↓")
print("Filtering")
print("      ↓")
print("filtered_ioc.txt")
print("      ↓")
print("Normalization")
print("      ↓")
print("normalized_ioc.txt")
print("=" * 55)

