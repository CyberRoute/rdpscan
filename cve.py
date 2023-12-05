import argparse
import requests

def get_cves_for_windows_version(cpe_name):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    search_url = f"{base_url}?cpeName={cpe_name}"

    response = requests.get(search_url)
    if response.status_code == 200:
        cve_data = response.json()
        vulnerabilities = cve_data.get("vulnerabilities", [])
        return [cve["cve"]["id"] for cve in vulnerabilities]
    else:
        print(f"Error: Unable to fetch CVEs. Status code: {response.status_code}")
        return []

def get_cves_for_given_cpe(cpe):
    cves = get_cves_for_windows_version(cpe)

    if cves:
        print(f"CVEs for Windows version {cpe}:")
        for cve in cves:
            print(cve)
    else:
        print(f"No CVEs found for Windows version {cpe}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch CVEs for a given Windows version CPE.")
    parser.add_argument("-cpe", "--cpe", help="CPE string for Windows version")

    args = parser.parse_args()

    if args.cpe:
        get_cves_for_given_cpe(args.cpe)
    else:
        print("Please provide a valid CPE string using the -cpe option.")
