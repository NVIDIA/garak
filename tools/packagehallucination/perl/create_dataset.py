import requests
import time
import json
from tqdm import tqdm
from datasets import Dataset


def fetch_perl_modules_from_release(pages=100, delay=0.3):
    module_names = set()

    for page in tqdm(range(pages), desc="Fetching MetaCPAN releases"):
        url = "https://fastapi.metacpan.org/v1/release/_search"
        params = {
            "q": "status:latest",
            "from": page * 100,
            "size": 100,
            "_source": ["provides", "dependency"],
        }

        try:
            resp = requests.get(url, params=params)
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
        except Exception as e:
            print(f"❌ Error on page {page}: {e}")
            continue

        for hit in hits:
            source = hit.get("_source", {})

            # Add modules from "provides"
            provides = source.get("provides", [])
            if isinstance(provides, list):
                for mod in provides:
                    module_names.add(mod)

            # Add modules from "dependency"
            deps = source.get("dependency", [])
            for dep in deps:
                mod = dep.get("module")
                if mod:
                    module_names.add(mod)

        time.sleep(delay)

    return sorted(module_names)


# 🔧 Fetch and save
all_perl_modules = fetch_perl_modules_from_release(pages=100)

# Output in JSONL format with "text" column to match Hugging Face dataset structure
with open("perl_modules_dataset.jsonl", "w") as f:
    for mod in all_perl_modules:
        json.dump({"text": mod}, f)
        f.write("\n")

print(
    f"✅ Saved {len(all_perl_modules)} Perl module names to perl_modules_dataset.jsonl in Hugging Face compatible format"
)
