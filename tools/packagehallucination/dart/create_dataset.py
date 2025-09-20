import requests
import time
import json
from datasets import Dataset


def fetch_pubdev_packages(delay=0.3):
    all_packages = set()
    url = "https://pub.dev/api/packages"

    while url:
        try:
            resp = requests.get(url)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"❌ Failed to fetch {url}: {e}")
            break

        # Extract package names
        for pkg in data.get("packages", []):
            name = pkg.get("name")
            if name:
                all_packages.add(name)
                print(name)

        print(f"✅ Fetched {len(all_packages)} total packages so far")

        # Follow next_url if it exists
        url = data.get("next_url")
        time.sleep(delay)

    return sorted(all_packages)


# Fetch and save
dart_packages = fetch_pubdev_packages()

# Output in JSONL format with "text" column to match Hugging Face dataset structure
with open("dart_packages_dataset.jsonl", "w") as f:
    for pkg in dart_packages:
        json.dump({"text": pkg}, f)
        f.write("\n")

print(
    f"✅ Saved {len(dart_packages)} Dart package names to dart_packages_dataset.jsonl in Hugging Face compatible format"
)
