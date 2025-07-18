import time
import requests
from datetime import datetime, timezone
import backoff
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

TIME_FORMAT = "%Y-%m-%d %H:%M:%S %z"

@backoff.on_exception(backoff.expo,
                      (requests.exceptions.RequestException, requests.exceptions.HTTPError),
                      max_tries=5)
def get_package_first_seen(package_name):
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        created_date = data.get('time', {}).get('created', 'N/A')
        # Parse the ISO format date and format it according to TIME_FORMAT
        dt = datetime.fromisoformat(created_date)
        dt = dt.replace(tzinfo=timezone.utc)
        created_date = dt.strftime(TIME_FORMAT)
    except requests.RequestException as e:
        created_date = f"Error: {str(e)}"
        print(f'Error getting data for {package_name}: {created_date}')

    return created_date

def main():
    # names.json from https://github.com/nice-registry/all-the-package-names/blob/master/names.json
    input_file = 'names.json'
    output_file = 'npm_packages3.tsv'
    processed = 0
    included = 0
    excluded = 0
    errors = 0
    start_time = time.time()

    # Read the JSON file into a Python list
    with open(input_file, 'r') as infile:
        package_names = json.load(infile)

    total_packages = len(package_names)
    print(f"Starting to process {total_packages} npm packages...")

    # Processes packages in parallel within batches
    batch_size = 1000
    batches = [package_names[i:i+batch_size] for i in range(0, len(package_names), batch_size)]

    with open(output_file, 'a') as outfile:
        outfile.write("text\tpackage_first_seen\n")
        for batch in batches:
            batch_results = []
            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                future_to_package = {executor.submit(get_package_first_seen, package): package for package in batch}
                
                for future in as_completed(future_to_package):
                    package = future_to_package[future]
                    creation_date = future.result()
                    batch_results.append((package, creation_date))
            
            batch_output = []
            for package, creation_date in batch_results:
                if creation_date:
                    batch_output.append(f"{package}\t{creation_date}")
                    included += 1
                    status = "Included"
                else:
                    excluded += 1
                    status = "Error" if "Error:" in str(creation_date) else "Excluded"
                
                processed += 1
                
                if "Error:" in str(creation_date):
                    errors += 1
            
            outfile.write("\n".join(batch_output) + "\n")
            outfile.flush()
            
            # Progress reporting
            elapsed_time = time.time() - start_time
            packages_per_second = processed / elapsed_time
            estimated_total_time = total_packages / packages_per_second
            estimated_remaining_time = estimated_total_time - elapsed_time
            
            print(f"Processed: {processed}/{total_packages} ({processed/total_packages*100:.2f}%)")
            print(f"Included: {included}, Excluded: {excluded}, Errors: {errors}")
            print(f"Elapsed time: {elapsed_time:.2f} seconds")
            print(f"Estimated remaining time: {estimated_remaining_time:.2f} seconds")
            print(f"Processing speed: {packages_per_second:.2f} packages/second")
            print("-" * 50)

    print(f"Filtering complete. Results saved in {output_file}")
    print(f"Total packages processed: {processed}")
    print(f"Packages included: {included}")
    print(f"Packages excluded: {excluded}")
    print(f"Packages with errors: {errors}")
    print(f"Total execution time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
