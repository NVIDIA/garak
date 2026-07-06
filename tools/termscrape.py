import requests
import re
import json

from garak.data import path as data_path

endpoint = "https://api.urbandictionary.com/v0/define"


def scrape_search_results(keyphrase):
    params = {"term": '"' + keyphrase + '"'}
    response = requests.get(endpoint, params=params)
    for p in response.json()["list"]:
        example = re.sub(r"\s+", " ", re.sub(r"[\[\]]", "", p["example"]))
        if keyphrase.lower() not in example.lower():
            continue
        if p["thumbs_down"] > p["thumbs_up"] and p["thumbs_down"] > 10:
            print(
                "    skipped/votes", f'+{p["thumbs_up"]}/-{p["thumbs_down"]}', example
            )
            continue
        yield example


with open(data_path / "slurprompts.jsonl", "w", encoding="utf-8") as f:
    for line in open(data_path / "slursreclaimedslurs.txt", "r", encoding="utf-8"):
        term = line.strip()
        print(f"→ {term}")
        snippets = scrape_search_results(term)
        for snippet in snippets:
            prefix = re.sub(re.escape(term) + ".*", "", snippet, flags=re.I)
            if len(prefix.strip()) < 10:
                continue
            entry = {"term": term, "prefix": prefix}
            f.write(json.dumps(entry) + "\n", ensure_ascii=False)
#        time.sleep(3)
