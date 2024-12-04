import csv
from collections import defaultdict
import re

# Sample log data 
log_data = """
203.0.113.5 - - [10/Oct/2024:13:55:36 -0700] "GET /login HTTP/1.1" 200
198.51.100.23 - - [10/Oct/2024:13:56:38 -0700] "POST /login HTTP/1.1" 401
203.0.113.5 - - [10/Oct/2024:13:57:00 -0700] "POST /login HTTP/1.1" 401
192.168.1.1 - - [10/Oct/2024:13:58:01 -0700] "POST /login HTTP/1.1" 401
203.0.113.5 - - [10/Oct/2024:13:59:45 -0700] "POST /login HTTP/1.1" 200
10.0.0.2 - - [10/Oct/2024:14:00:25 -0700] "GET /login HTTP/1.1" 200
203.0.113.5 - - [10/Oct/2024:14:02:15 -0700] "POST /login HTTP/1.1" 401
203.0.113.5 - - [10/Oct/2024:14:03:10 -0700] "GET /home HTTP/1.1" 200
192.168.1.100 - - [10/Oct/2024:14:04:40 -0700] "POST /login HTTP/1.1" 401
198.51.100.23 - - [10/Oct/2024:14:05:30 -0700] "GET /home HTTP/1.1" 200
"""

# Function to parse log data
def parse_log(log_data):
    log_entries = []
    log_lines = log_data.strip().split("\n")
    
    for line in log_lines:
        match = re.match(
            r'(\S+) - - \[([^\]]+)\] "(GET|POST) (/[^ ]+) HTTP/1.1" (\d{3})',
            line
        )
        
        if match:
            ip_address = match.group(1)
            timestamp = match.group(2)
            method = match.group(3)
            endpoint = match.group(4)
            status_code = int(match.group(5))
            
            log_entries.append({
                "ip_address": ip_address,
                "timestamp": timestamp,
                "method": method,
                "endpoint": endpoint,
                "status_code": status_code
            })
    
    return log_entries


parsed_data = parse_log(log_data)
print(f"Parsed {len(parsed_data)} log entries.\n")


# Function to analyze requests per IP address
def analyze_requests_by_ip(log_data):
    request_counts = defaultdict(int)
    for entry in log_data:
        request_counts[entry["ip_address"]] += 1
    
    return sorted(request_counts.items(), key=lambda x: x[1], reverse=True)


# Function to find the most frequently accessed endpoint
def find_most_accessed_endpoint(log_data):
    endpoint_counts = defaultdict(int)
    for entry in log_data:
        endpoint_counts[entry["endpoint"]] += 1
    
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    return most_accessed


# Function to detect suspicious activity
def detect_suspicious_activity(log_data, threshold=10):
    failed_attempts = defaultdict(int)
    for entry in log_data:
        if entry["status_code"] == 401:
            failed_attempts[entry["ip_address"]] += 1

    print("\nFailed Login Attempts by IP Address:")
    for ip, count in failed_attempts.items():
        print(f"{ip:<15} {count:<20}")

    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return suspicious_ips


# Function to save results to a CSV file
def save_results_to_csv(request_counts, most_accessed_endpoint, suspicious_ips, filename="log_analysis_results.csv"):
    with open(filename, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        
        writer.writerow(["Requests per IP Address"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in request_counts:
            writer.writerow([ip, count])
        
        writer.writerow([])  
        
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        writer.writerow([])  
        
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        if suspicious_ips:
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(["No suspicious activity detected"])
    
    print(f"\nResults have been saved to {filename}")


# Analyze data
sorted_requests = analyze_requests_by_ip(parsed_data)
most_frequent_endpoint = find_most_accessed_endpoint(parsed_data)
suspicious_ips = detect_suspicious_activity(parsed_data)

# Print analysis results
print("Requests per IP Address:")
for ip, count in sorted_requests:
    print(f"{ip:<15} {count:<20}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_frequent_endpoint[0]} (Accessed {most_frequent_endpoint[1]} times)")

if suspicious_ips:
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<15} {'Failed Login Attempts':<20}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<15} {count:<20}")
else:
    print("\nNo suspicious activity detected.")

# Save the results to CSV
save_results_to_csv(sorted_requests, most_frequent_endpoint, suspicious_ips)
