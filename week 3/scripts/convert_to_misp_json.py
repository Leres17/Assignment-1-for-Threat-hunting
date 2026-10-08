import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "enriched_ioc.txt"
OUTPUT_FILE = BASE_DIR / "misp_event.json"


def parse_line(line):
    data = {}

    for part in line.split("|"):
        part = part.strip()

        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        data[key.strip()] = value.strip()

    return data


def build_comment(data):
    comments = []

    if data.get("Type"):
        comments.append(f"Threat Type: {data['Type']}")

    if data.get("Source"):
        comments.append(f"Source: {data['Source']}")

    if data.get("Date"):
        comments.append(f"Date: {data['Date']}")

    # VirusTotal enrichment
    if data.get("VT_Country"):
        comments.append(f"VT Country: {data['VT_Country']}")

    if data.get("VT_ASN"):
        comments.append(f"VT ASN: {data['VT_ASN']}")

    if data.get("VT_AS_Owner"):
        comments.append(f"VT AS Owner: {data['VT_AS_Owner']}")

    if data.get("VT_Malicious"):
        comments.append(f"VT Malicious: {data['VT_Malicious']}")

    if data.get("VT_Suspicious"):
        comments.append(f"VT Suspicious: {data['VT_Suspicious']}")

    if data.get("VT_Harmless"):
        comments.append(f"VT Harmless: {data['VT_Harmless']}")

    if data.get("VT_Undetected"):
        comments.append(f"VT Undetected: {data['VT_Undetected']}")

    # Shodan enrichment
    if data.get("Shodan_Country"):
        comments.append(f"Shodan Country: {data['Shodan_Country']}")

    if data.get("Shodan_City"):
        comments.append(f"Shodan City: {data['Shodan_City']}")

    if data.get("Shodan_Organization"):
        comments.append(
            f"Shodan Organization: {data['Shodan_Organization']}"
        )

    if data.get("Shodan_ISP"):
        comments.append(f"Shodan ISP: {data['Shodan_ISP']}")

    if data.get("Shodan_ASN"):
        comments.append(f"Shodan ASN: {data['Shodan_ASN']}")

    if data.get("Shodan_Ports"):
        comments.append(f"Shodan Ports: {data['Shodan_Ports']}")

    if data.get("Shodan_Hostnames"):
        comments.append(
            f"Shodan Hostnames: {data['Shodan_Hostnames']}"
        )

    return " | ".join(comments)

# Check input file

if not INPUT_FILE.exists():
    print("ERROR: enriched_ioc.txt was not found.")
    print()
    print("Expected file:")
    print(INPUT_FILE)
    exit()

# Read enriched IOC data

records = []

with open(INPUT_FILE, "r", encoding="utf-8") as file:

    for line in file:

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        data = parse_line(line)

        if data:
            records.append(data)


# Create MISP attributes

attributes = []

for data in records:

    ip = data.get("IP", "").strip()

    if not ip:
        continue

    attribute = {
        "type": "ip-src",
        "category": "Network activity",
        "value": ip,
        "to_ids": True,
        "comment": build_comment(data)
    }

    attributes.append(attribute)


# Create MISP Event

misp_event = {
    "Event": {
        "info": "DDoS Threat Intelligence - Enriched IOC",
        "distribution": "0",
        "analysis": "0",
        "threat_level_id": "2",
        "Attribute": attributes
    }
}


# Write JSON file

with open(OUTPUT_FILE, "w", encoding="utf-8") as file:

    json.dump(
        misp_event,
        file,
        indent=4,
        ensure_ascii=False
    )


# Result

print("=" * 60)
print("MISP JSON CONVERSION COMPLETED")
print("=" * 60)

print(f"Input records:      {len(records)}")
print(f"MISP attributes:    {len(attributes)}")

print()
print("Output:")
print(OUTPUT_FILE)

print()
print("Pipeline:")
print("enriched_ioc.txt")
print("        ↓")
print("convert_to_misp_json.py")
print("        ↓")
print("misp_event.json")

print("=" * 60)