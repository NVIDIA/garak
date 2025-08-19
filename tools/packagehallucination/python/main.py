import requests
from datetime import datetime, timezone
import csv
import backoff
from concurrent.futures import ThreadPoolExecutor, as_completed

TIME_FORMAT = "%Y-%m-%d %H:%M:%S %z"

def get_all_packages():
    url = "https://pypi.org/simple/"
    response = requests.get(url)
    packages = response.text.split("\n")
    return [pkg.split("/")[2] for pkg in packages if "a href" in pkg]

@backoff.on_exception(backoff.expo,
                      (requests.exceptions.RequestException, requests.exceptions.HTTPError),
                      max_tries=5)
def get_package_first_seen(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    releases = data.get("releases", {})
    if releases:
        oldest_release = min(releases.keys(), key=lambda x: releases[x][0]['upload_time'] if releases[x] else '9999-99-99')
        if releases[oldest_release] and releases[oldest_release][0].get("upload_time"):
            # Parse the upload time and format it according to TIME_FORMAT
            upload_time = releases[oldest_release][0]["upload_time"]
            try:
                # Parse the time (PyPI times are in UTC)
                dt = datetime.fromisoformat(upload_time)
                dt = dt.replace(tzinfo=timezone.utc)
                return dt.strftime(TIME_FORMAT)
            except ValueError:
                return None
    return None

def main():
    output_file = "pypi_20241007_NEW.tsv"
    packages = get_all_packages()
    processed = 0
    total_packages = len(packages)
    print(f"Starting to process {total_packages} PyPI packages...")
    
    batch_size = 1000
    batches = [packages[i:i+batch_size] for i in range(0, total_packages, batch_size)]
    
    try:
        with open(output_file, "a", newline='') as outfile:
            tsv_writer = csv.writer(outfile, delimiter='\t')
            tsv_writer.writerow(["text", "package_first_seen"])

            for batch in batches:
                batch_results = []
                with ThreadPoolExecutor(max_workers=batch_size) as executor:
                    future_to_package = {executor.submit(get_package_first_seen, package): package for package in batch}
                    
                    for future in as_completed(future_to_package):
                        package = future_to_package[future]
                        try:
                            creation_date = future.result()
                            batch_results.append((package, creation_date))
                            processed += 1
                            if processed % 100 == 0:
                                print(f"Processed: {processed}/{total_packages} ({processed/total_packages*100:.2f}%)")
                        except Exception as e:
                            print(f"Error processing {package}: {str(e)}")
                
                for package, creation_date in batch_results:
                    if creation_date:
                        tsv_writer.writerow([package, creation_date])
                    else:
                        print(f"No creation date found for {package}")
                
                outfile.flush()
                print(f"Batch completed. Total processed: {processed}/{total_packages} ({processed/total_packages*100:.2f}%)")
                print("*"*50)
    
    except IOError as e:
        print(f"Error writing to file: {str(e)}")
    
    print(f"Done! Results saved in {output_file}")

if __name__ == "__main__":
    main()
