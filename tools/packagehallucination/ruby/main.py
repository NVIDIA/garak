import time
import requests
from datetime import datetime, timezone
import backoff
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S %z"

@backoff.on_exception(backoff.expo,
                      (requests.exceptions.RequestException, requests.exceptions.HTTPError),
                      max_tries=5)
def get_package_first_seen(gem_name):
    url = f"https://rubygems.org/api/v1/versions/{gem_name}.json"
    response = requests.get(url, timeout=30)
    response.raise_for_status()  # This will raise an HTTPError for bad responses

    versions = response.json()

    # Sort versions by creation date and get the earliest one
    earliest_version = min(versions, key=lambda v: datetime.strptime(v['created_at'], INPUT_TIME_FORMAT))
    
    # Parse and format the date
    creation_datetime = datetime.strptime(earliest_version['created_at'], INPUT_TIME_FORMAT)
    creation_datetime = creation_datetime.replace(tzinfo=timezone.utc)
    return creation_datetime.strftime(TIME_FORMAT)

def main():
    # gems.txt is the output from the `gem list --remote` command
    input_file = 'gems.txt'
    output_file = 'filtered_gems.tsv'
    batch_size = 100

    # Read all gem names first
    with open(input_file, 'r') as infile:
        all_gems = [line.strip().split(" (")[0] for line in infile]

    total_gems = len(all_gems)
    processed = 0
    included = 0
    excluded = 0
    errors = 0
    start_time = time.time()

    # Create batches
    batches = [all_gems[i:i+batch_size] for i in range(0, total_gems, batch_size)]

    print(f"Starting to process {total_gems} gems...")

    with open(output_file, 'a') as outfile:
        outfile.write(f"text\tpackage_first_seen\n")

        for batch in batches:
            batch_results = []
            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                future_to_gem = {executor.submit(get_package_first_seen, gem_name): gem_name for gem_name in batch}
                
                for future in as_completed(future_to_gem):
                    gem_name = future_to_gem[future]
                    try:
                        formatted_date = future.result()
                        batch_results.append((gem_name, formatted_date))
                        included += 1
                        status = "Included"
                    except Exception as e:
                        print(f"Error processing gem '{gem_name}': {e}")
                        errors += 1
                        status = "Error"

                    processed += 1

                    if processed % 100 == 0 or processed == total_gems:
                        elapsed_time = time.time() - start_time
                        gems_per_second = processed / elapsed_time
                        estimated_total_time = total_gems / gems_per_second
                        estimated_remaining_time = estimated_total_time - elapsed_time

                        print(f"Processed: {processed}/{total_gems} ({processed/total_gems*100:.2f}%)")
                        print(f"Included: {included}, Excluded: {excluded}, Errors: {errors}")
                        print(f"Elapsed time: {elapsed_time:.2f} seconds")
                        print(f"Estimated remaining time: {estimated_remaining_time:.2f} seconds")
                        print(f"Processing speed: {gems_per_second:.2f} gems/second")
                        print("-" * 50)
            
            # Write batch results
            for gem_name, formatted_date in batch_results:
                if formatted_date:
                    outfile.write(f"{gem_name}\t{formatted_date}\n")
            outfile.flush()
            print(f"Batch completed. Total processed: {processed}/{total_gems} ({processed/total_gems*100:.2f}%)")
            print("*"*50)

    print(f"Filtering complete. Results saved in {output_file}")
    print(f"Total gems processed: {processed}")
    print(f"Gems included: {included}")
    print(f"Gems excluded: {excluded}")
    print(f"Gems with errors: {errors}")
    print(f"Total execution time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
