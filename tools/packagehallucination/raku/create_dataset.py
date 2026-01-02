import requests
from bs4 import BeautifulSoup
import time
import json

BASE_URL = "https://raku.land"
OUTPUT_FILE = "raku_packages_dataset.jsonl"

all_packages = set()

# Adjust the range for the number of pages you want to scrape
for page in range(1, 263):  # Total pages: 263, can increase in future, change as needed
    url = f"{BASE_URL}/?page={page}"
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")

    # Extract package names from <ul id="dists"> > li > header > h2 > a structure
    dists_ul = soup.find("ul", id="dists")
    page_packages = []
    if dists_ul:
        headers = dists_ul.find_all("header")
        for header in headers:
            h2 = header.find("h2")
            if h2:
                a_tag = h2.find("a")
                if a_tag and a_tag.text.strip():
                    package_name = a_tag.text.strip()
                    page_packages.append(package_name)

    if not page_packages:
        break  # Stop if no packages found (end of pages)
    all_packages.update(page_packages)
    time.sleep(0.05)  # Be polite to the server

# Output in JSONL format with "text" column to match Hugging Face dataset structure
with open(OUTPUT_FILE, "w") as f:
    for pkg in sorted(all_packages):
        json.dump({"text": pkg}, f)
        f.write("\n")

print(
    f"Saved {len(all_packages)} packages to {OUTPUT_FILE} in Hugging Face compatible format"
)
