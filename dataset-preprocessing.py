import csv

INPUT_FILE = "recent.csv"
OUTPUT_FILE = "cleaned.txt"

def format_ioc(ioc_type, ioc_value):
    t = ioc_type.lower().strip()
    v = ioc_value.strip().replace('"', "")

    if "ip" in t:
        return f"IP:{v.split(':')[0]}"
    elif "url" in t:
        return f"URL:{v}"
    elif "hash" in t:
        return f"HASH:{v}"
    elif "domain" in t:
        return f"DOMAIN:{v}"
    return None

results = []
seen = set()

with open(INPUT_FILE, "r", encoding="utf-8", newline="") as f:
    reader = csv.reader(f)

    for row in reader:
        # skip comments / empty rows
        if not row or (len(row) > 0 and row[0].startswith("#")):
            continue

        # require at least 4 columns
        if len(row) < 4:
            continue

        ioc_value = row[2]
        ioc_type = row[3]

        formatted = format_ioc(ioc_type, ioc_value)

        if formatted and formatted not in seen:
            seen.add(formatted)
            results.append(formatted)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for item in results:
        f.write(item + "\n")

print(f"Saved {len(results)} entries to {OUTPUT_FILE}")
