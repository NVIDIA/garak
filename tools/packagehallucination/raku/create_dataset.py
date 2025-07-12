import requests
from bs4 import BeautifulSoup
import time

BASE_URL = "https://raku.land"
OUTPUT_FILE = "all_raku_packages.txt"

all_packages = set()

# Adjust the range for the number of pages you want to scrape
for page in range(1, 263):  # Total pages: 263, can increase in future, change as needed
    url = f"{BASE_URL}/?page={page}"
    resp = requests.get(url)
    soup = BeautifulSoup(resp.text, 'html.parser')
    links = soup.find_all('a')
    page_packages = [a.text.strip() for a in links if '::' in a.text]
    if not page_packages:
        break  # Stop if no packages found (end of pages)
    all_packages.update(page_packages)
    time.sleep(0.05)  # Be polite to the server

with open(OUTPUT_FILE, 'w') as f:
    for pkg in sorted(all_packages):
        f.write(pkg + '\n')

print(f"Saved {len(all_packages)} packages to {OUTPUT_FILE}")
