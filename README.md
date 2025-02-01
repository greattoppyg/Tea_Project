# Malware Detection Script


import os
import hashlib
import psutil
import requests

# Known malware hash database (Add more hashes as needed)
KNOWN_MALWARE_HASHES = {
    "5d41402abc4b2a76b9719d911017c592",  # Example hash (change this)
    "7d793037a0760186574b0282f2f435e7"
}

# Function to calculate SHA-256 hash of a file
def calculate_file_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash
    except Exception as e:
        print(f"Error hashing {file_path}: {e}")
        return None

# Function to scan a directory for malware
def scan_directory(directory):
    print(f"Scanning directory: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)
            if file_hash in KNOWN_MALWARE_HASHES:
                print(f"⚠️ WARNING: Malware detected! {file_path}")
            else:
                print(f"✔ Safe: {file_path}")

# Function to check running processes for suspicious activity
def check_running_processes():
    print("\nChecking running processes...")
    suspicious_keywords = ["keylogger", "trojan", "ransomware", "bitcoin_miner"]
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            process_name = proc.info["name"].lower()
            if any(keyword in process_name for keyword in suspicious_keywords):
                print(f"⚠️ Suspicious process detected: {proc.info['name']} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

# (Optional) Function to check a file against VirusTotal
def check_with_virustotal(file_path, api_key="YOUR_VIRUSTOTAL_API_KEY"):
    file_hash = calculate_file_hash(file_path)
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        if result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            print(f"⚠️ File flagged as malware: {file_path}")
        else:
            print(f"✔ File is clean: {file_path}")
    else:
        print("Could not check with VirusTotal. Check API key or internet connection.")

# Main execution
if __name__ == "__main__":
    scan_directory("/path/to/scan")  # Change path as needed
    check_running_processes()
