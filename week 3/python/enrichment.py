import requests
from pathlib import Path
import time

# FILES

BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "normalized_ioc.txt"
OUTPUT_FILE = BASE_DIR / "enriched_ioc.txt"


# API KEYS

SHODAN_API_KEY = "EpbF0dhZGiyfMms7G8O1VgSg25tx4Q8E"
VIRUSTOTAL_API_KEY = "000e46ee379d2458cbc861a025de7be0791d8fa2fe4f71ec496020de6e5b61b6"


# PARSING

def parse_line(line):
    """
    Convert one IOC line into a dictionary.

    Example:

    IP=8.8.8.8 | Domain=google.com | Source=Test

    becomes:

    {
        "IP": "8.8.8.8",
        "Domain": "google.com",
        "Source": "Test"
    }
    """

    data = {}

    for part in line.split("|"):

        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)

        data[key.strip()] = value.strip()

    return data



# SHODAN


def enrich_with_shodan(ip):
    """
    Get host information from Shodan.
    """

    url = f"https://api.shodan.io/shodan/host/{ip}"

    params = {
        "key": SHODAN_API_KEY
    }

    try:

        response = requests.get(
            url,
            params=params,
            timeout=15
        )

        if response.status_code != 200:
            print(
                f"  Shodan: no data "
                f"(HTTP {response.status_code})"
            )
            return {}

        return response.json()

    except requests.RequestException as error:

        print(f"  Shodan error: {error}")

        return {}



# VIRUSTOTAL


def enrich_with_virustotal(ip):
    """
    Get IP information from VirusTotal.
    """

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )

        if response.status_code != 200:
            print(
                f"  VirusTotal: no data "
                f"(HTTP {response.status_code})"
            )
            return {}

        return response.json()

    except requests.RequestException as error:

        print(f"  VirusTotal error: {error}")

        return {}



# EXTRACT SHODAN DATA


def extract_shodan_data(data):
    """
    Extract only useful fields from Shodan response.
    """

    if not data:
        return {}

    return {
        "Shodan_Country": data.get("country_name", ""),
        "Shodan_City": data.get("city", ""),
        "Shodan_Organization": data.get("org", ""),
        "Shodan_ISP": data.get("isp", ""),
        "Shodan_ASN": data.get("asn", ""),
        "Shodan_Ports": ",".join(
            str(port)
            for port in data.get("ports", [])
        ),
        "Shodan_Hostnames": ",".join(
            data.get("hostnames", [])
        )
    }



# EXTRACT VIRUSTOTAL DATA


def extract_virustotal_data(data):
    """
    Extract useful information from VirusTotal response.
    """

    if not data:
        return {}

    attributes = data.get(
        "data",
        {}
    ).get(
        "attributes",
        {}
    )

    analysis_stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    return {
        "VT_Country": attributes.get("country", ""),
        "VT_ASN": attributes.get("asn", ""),
        "VT_AS_Owner": attributes.get("as_owner", ""),
        "VT_Malicious": analysis_stats.get("malicious", 0),
        "VT_Suspicious": analysis_stats.get("suspicious", 0),
        "VT_Harmless": analysis_stats.get("harmless", 0),
        "VT_Undetected": analysis_stats.get("undetected", 0)
    }



# MAIN


if not INPUT_FILE.exists():

    print("ERROR: normalized_ioc.txt was not found.")
    print()
    print("Expected file:")
    print(INPUT_FILE)

    exit()


# Read normalized data
with open(
    INPUT_FILE,
    "r",
    encoding="utf-8"
) as file:

    lines = file.readlines()


enriched_records = []

print("=" * 60)
print("IOC ENRICHMENT")
print("=" * 60)


for number, line in enumerate(lines, start=1):

    line = line.strip()

    if not line:
        continue

    data = parse_line(line)

    ip = data.get("IP", "")

    if not ip:
        print(
            f"[{number}] Skipping record "
            f"because IP is missing."
        )

        continue

    print()
    print(f"[{number}] Processing IP: {ip}")


    # Shodan


    print("  Querying Shodan...")

    shodan_raw = enrich_with_shodan(ip)

    shodan_data = extract_shodan_data(
        shodan_raw
    )


    # VirusTotal


    print("  Querying VirusTotal...")

    virustotal_raw = enrich_with_virustotal(ip)

    virustotal_data = extract_virustotal_data(
        virustotal_raw
    )


    # Combine original + enrichment


    result = data.copy()

    result.update(shodan_data)
    result.update(virustotal_data)

    enriched_records.append(result)

    # Small delay between requests
    time.sleep(1)



# SAVE RESULTS


with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    for record in enriched_records:

        fields = []

        for key, value in record.items():

            if value == "":
                continue

            fields.append(
                f"{key}={value}"
            )

        file.write(
            " | ".join(fields)
            + "\n\n"
        )



# RESULTS


print()
print("=" * 60)
print("ENRICHMENT COMPLETED")
print("=" * 60)

print(f"Input records:  {len(lines)}")
print(f"Enriched:       {len(enriched_records)}")

print()
print("Output:")
print(OUTPUT_FILE)

print()
print("Pipeline:")
print("normalized_ioc.txt")
print("        ↓")
print("     Shodan")
print("        +")
print("   VirusTotal")
print("        ↓")
print("enriched_ioc.txt")
print("=" * 60)

