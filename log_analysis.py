import re
import csv
from collections import Counter, defaultdict

# Function to read log file
def read_log_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return []

# Function to count requests per IP
def count_requests_per_ip(log_lines):
    ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
    ip_counts = Counter(re.findall(ip_pattern, ' '.join(log_lines)))
    return ip_counts.most_common()

# Function to identify the most accessed endpoint
def most_accessed_endpoint(log_lines):
    endpoint_pattern = re.compile(r'\"[A-Z]+\s(\/[^\s]*)')
    endpoints = re.findall(endpoint_pattern, ' '.join(log_lines))
    endpoint_counts = Counter(endpoints)
    most_common = endpoint_counts.most_common(1)
    return most_common[0] if most_common else ("None", 0)

# Function to detect suspicious activity
def detect_suspicious_activity(log_lines, threshold=1):
    failed_login_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*?\] ".*?" 401 \d+|(\d+\.\d+\.\d+\.\d+).*"Invalid credentials"')
    failed_attempts = []

    for line in log_lines:
        match = failed_login_pattern.findall(line)
        if match:
            for ip_group in match:
                failed_attempts.append(ip_group[0] or ip_group[1])  
    ip_counts = Counter(failed_attempts)
    suspicious_ips = {ip: count for ip, count in ip_counts.items() if count > threshold}
    return suspicious_ips

# Function to save results to CSV
def save_to_csv(ip_data, endpoint_data, suspicious_data, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_data)
        writer.writerow([])

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(endpoint_data)
        writer.writerow([])

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_data.items())
        writer.writerow([])

# Main function to execute the script
def main():
    log_file = "sample.log"  
    output_file = "log_analysis_results.csv"
    
    log_lines = read_log_file(log_file)
    if not log_lines:
        return

    # Analyze log data
    ip_counts = count_requests_per_ip(log_lines)
    most_common_endpoint = most_accessed_endpoint(log_lines)
    suspicious_ips = detect_suspicious_activity(log_lines)

    # Print results to terminal
    print("\nRequests per IP:")
    for ip, count in ip_counts:
        print(f"{ip}: {count}")

    print("\nMost Accessed Endpoint:")
    print(f"{most_common_endpoint[0]}: {most_common_endpoint[1]} accesses")

    print("\nSuspicious Activity:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count} failed login attempts")

    # Save results to CSV
    save_to_csv(ip_counts, most_common_endpoint, suspicious_ips, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
