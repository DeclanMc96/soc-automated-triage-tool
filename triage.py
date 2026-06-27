import argparse
import requests
import os
from dotenv import load_dotenv

# Load the hidden environment variables from the .env file
load_dotenv()

# Securely fetch the keys from the operating system environment
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not ABUSEIPDB_API_KEY or not VIRUSTOTAL_API_KEY:
    print("[!] FATAL ERROR: API keys are missing. Please check your .env file.")
    exit(1)


def check_abuseipdb(ip_address):
    """
    Queries the AbuseIPDB API v2 to retrieve reputation data for a specific IP address.
    Returns the 'data' block from the JSON response if successful, otherwise returns None.
    """
    # The official API endpoint for checking a single IP address reputation
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    # Parameters expected by the AbuseIPDB API
    # maxAgeInDays='90' limits the search to reports submitted within the last 90 days
    querystring = {
        'ipAddress': ip_address, 
        'maxAgeInDays': '90'
    }
    
    # Custom headers required by AbuseIPDB for authentication and format negotiation
    headers = {
        'Accept': 'application/json',  # We explicitly demand the response data format to be JSON
        'Key': ABUSEIPDB_API_KEY       # Pass our unique API token for authentication
    }
    
    try:
        # Execute an HTTP GET request to the target endpoint with headers and parameters
        response = requests.get(url, headers=headers, params=querystring)
        
        # HTTP status code 200 indicates the server processed the request successfully
        if response.status_code == 200:
            # Extract the raw JSON text from the response and isolate the nested 'data' dictionary
            return response.json()['data']
    except Exception as e:
        # Catch network dropping, DNS failures, or connection timeouts safely without crashing the script
        print(f"[!] AbuseIPDB Connection failed: {e}")
    
    # Return None if the status code was not 200 or if an exception occurred
    return None

def check_virustotal(ip_address):
    """
    Queries the VirusTotal API v3 to check if an IP address is flagged by global security vendors.
    Returns the 'attributes' nested dictionary from the JSON response if successful, otherwise None.
    """
    # VirusTotal API v3 uses a RESTful URL structure where the target IP is part of the path itself
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    # VirusTotal authentication requires the key to be passed in a specific header named 'x-apikey'
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        # Execute the HTTP GET request to VirusTotal
        response = requests.get(url, headers=headers)
        
        # Verify the request succeeded
        if response.status_code == 200:
            # Parse the JSON response. We use .get() to safely dig into nested fields
            # without triggering a KeyError if a field happens to be missing.
            return response.json().get('data', {}).get('attributes', {})
    except Exception as e:
        # Catch connection and routing exceptions gracefully
        print(f"[!] VirusTotal Connection failed: {e}")
        
    return None

def main():
    """
    The main execution engine of the script. Handles user input, calls the API functions,
    formats the output, and automatically compiles the text report file.
    """
    # Initialize the argument parser configuration object
    parser = argparse.ArgumentParser(description="SOC Triage Automation: Auto-Enrichment for IOCs")
    
    # Configure the mandatory command-line flag (-i or --ioc) that accepts the target IP
    parser.add_argument('-i', '--ioc', required=True, help="The IP address to analyse.")
    
    # Parse the arguments provided by the user in the terminal execution string
    args = parser.parse_args()
    
    # Extract the string input from the parsed arguments object
    target = args.ioc
    
    # Visual initialisation text blocks printed directly to the terminal screen
    print("-" * 50)
    print(f"[*] Initialising SOC Triage for IOC: {target}")
    print("[*] Gathering threat intelligence...")
    print("-" * 50 + "\n")
    
    # Trigger both API queries sequentially and store their returned data dictionaries
    abuse_data = check_abuseipdb(target)
    vt_data = check_virustotal(target)
    
    # Initialise an empty list to dynamically build our final text report line by line
    report_lines = []
    report_lines.append("="*40)
    report_lines.append(f"SOC AUTOMATED TRIAGE REPORT FOR: {target}")
    report_lines.append("="*40 + "\n")
    
    # Process and format the AbuseIPDB data block if the query returned valid information
    if abuse_data:
        report_lines.append("--- ABUSEIPDB RESULTS ---")
        report_lines.append(f"Abuse Score:     {abuse_data['abuseConfidenceScore']}%")
        report_lines.append(f"Whitelisted:     {abuse_data['isWhitelisted']}")
        report_lines.append(f"Usage Type:      {abuse_data['usageType']}")
        report_lines.append(f"Total Reports:   {abuse_data['totalReports']}\n")
        
    # Process and format the VirusTotal data block if the query returned valid information
    if vt_data:
        # Extract the malicious detection stats dictionary from the nested attributes
        stats = vt_data.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)  # Count of vendors marking it malicious
        total = sum(stats.values())            # Total count of all reporting security vendors
        
        report_lines.append("--- VIRUSTOTAL RESULTS ---")
        report_lines.append(f"Detections:      {malicious} / {total} engines")
        report_lines.append(f"Owner:           {vt_data.get('as_owner', 'Unknown')}")
        report_lines.append(f"Country Code:    {vt_data.get('country', 'Unknown')}\n")
        
    # Join all separate string elements in the list using newline breaks to create one large text block
    report_text = "\n".join(report_lines)
    
    # Output the completed, beautifully formatted threat report directly to the terminal
    print(report_text)
    
    # Dynamically generate a distinct output file name using the evaluated IP target
    filename = f"triage_report_{target}.txt"
    
    try:
        # Open the file in write mode ("w"). The 'with' context manager handles closing the file
        # safely even if the file-writing process hits an unexpected system error.
        with open(filename, "w") as f:
            f.write(report_text)
        print(f"[+] Automated triage complete. Report saved to: {filename}")
    except IOError as e:
        # Alert the user if the operating system blocks file creation due to permission or space limits
        print(f"[!] Failed to write report file to disk: {e}")

# Python boilerplate validation: guarantees this script executes only when run directly from the terminal
# (e.g. `python triage.py`), rather than when imported as a module inside another background application.
if __name__ == "__main__":
    main()