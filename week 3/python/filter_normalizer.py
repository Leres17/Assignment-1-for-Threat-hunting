import re
import ipaddress


INPUT_FILE = "raw_ioc.txt"
FILTERED_FILE = "filtered_ioc.txt"
NORMALIZED_FILE = "normalized_ioc.txt"


def parse_line(line):
    """
    Converts:
    IP=1.2.3.4 | Domain=example.com | Type=DDoS
    into a dictionary.

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


def is_valid_ip(value):
    try:
        ip = ipaddress.ip_address(value)

        # Remove private/local IP addresses
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False

        return True

    except ValueError:
        return False


def is_valid_domain(value):
    if not value:
        return False

    pattern = r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    return bool(re.match(pattern, value))


def is_valid_url(value):
    if not value:
        return False

    pattern = r"^https?://[^\s]+$"

    return bool(re.match(pattern, value, re.IGNORECASE))


def filter_data(lines):

    filtered = []
    seen = set()

    for line in lines:

        line = line.strip()

        # Empty line
        if not line:
            continue

        data = parse_line(line)

        # Check whether the line contains at least one usable IOC
        ip = data.get("IP", "")
        domain = data.get("Domain", "")
        url = data.get("URL", "")

        valid_ioc = False

        if ip and is_valid_ip(ip):
            valid_ioc = True

        if domain and is_valid_domain(domain):
            valid_ioc = True

        if url and is_valid_url(url):
            valid_ioc = True

        # No valid IOC → remove
        if not valid_ioc:
            continue

        # Remove exact duplicate lines
        normalized_line = line.lower()

        if normalized_line in seen:
            continue

        seen.add(normalized_line)

        filtered.append(line)

    return filtered


def normalize_data(lines):

    normalized = []

    for line in lines:

        data = parse_line(line)

        # Missing fields return an empty string
        ip = data.get("IP", "")
        domain = data.get("Domain", "")
        url = data.get("URL", "")
        ioc_type = data.get("Type", "")
        source = data.get("Source", "")
        date = data.get("Date", "")

        # Normalize values
        ip = ip.strip()

        domain = domain.strip().lower()

        url = url.strip()

        if url:
            url = url.lower()

        ioc_type = ioc_type.strip().lower()
        source = source.strip()
        date = date.strip()

        # Rebuild the line using the same structure
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


# =============================================================================
# MAIN 


with open(INPUT_FILE, "r", encoding="utf-8") as file:
    raw_data = file.readlines()


# FILTERING

filtered_data = filter_data(raw_data)

with open(FILTERED_FILE, "w", encoding="utf-8") as file:
    for line in filtered_data:
        file.write(line + "\n")


# NORMALIZATION

normalized_data = normalize_data(filtered_data)

with open(NORMALIZED_FILE, "w", encoding="utf-8") as file:
    for line in normalized_data:
        file.write(line + "\n")


print("Processing completed.")
print(f"Raw indicators:        {len(raw_data)}")
print(f"After filtering:       {len(filtered_data)}")
print(f"After normalization:   {len(normalized_data)}")