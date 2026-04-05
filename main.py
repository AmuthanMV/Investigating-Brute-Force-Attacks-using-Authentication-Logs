import re
from collections import defaultdict, Counter


def parse_log(file_path):
    log_entries = []

    pattern = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*?(Failed password|Accepted password).*?for (invalid user )?(\w+) from ([\d\.]+)'
    )

    with open(file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                timestamp = match.group(1)
                status = match.group(2)
                username = match.group(4)
                ip = match.group(5)

                log_entries.append({
                    'timestamp': timestamp,
                    'status': status,
                    'username': username,
                    'ip': ip
                })

    return log_entries



def analyze_logs(log_entries, threshold=5):
    failed_attempts_by_ip = defaultdict(int)
    failed_attempts_by_user = defaultdict(int)
    success_attempts_by_ip = defaultdict(int)
    success_after_fail = []

    total_failed = 0
    total_success = 0

    for entry in log_entries:
        ip = entry['ip']
        username = entry['username']
        status = entry['status']

        if status == "Failed password":
            total_failed += 1
            failed_attempts_by_ip[ip] += 1
            failed_attempts_by_user[username] += 1

        elif status == "Accepted password":
            total_success += 1
            success_attempts_by_ip[ip] += 1

            if failed_attempts_by_ip[ip] >= threshold:
                success_after_fail.append({
                    'ip': ip,
                    'username': username,
                    'failed_attempts_before_success': failed_attempts_by_ip[ip]
                })

    suspicious_ips = []
    for ip, count in failed_attempts_by_ip.items():
        if count >= threshold:
            suspicious_ips.append({
                'ip': ip,
                'failed_attempts': count
            })

    return {
        'total_logs': len(log_entries),
        'total_failed': total_failed,
        'total_success': total_success,
        'failed_attempts_by_ip': failed_attempts_by_ip,
        'failed_attempts_by_user': failed_attempts_by_user,
        'success_after_fail': success_after_fail,
        'suspicious_ips': suspicious_ips
    }


def display_results(results):
    print("=" * 65)
    print("     BRUTE FORCE ATTACK INVESTIGATION USING AUTHENTICATION LOGS")
    print("=" * 65)

    print("\n[1] OVERALL LOG SUMMARY")
    print("-" * 30)
    print(f"Total Log Entries       : {results['total_logs']}")
    print(f"Total Failed Logins     : {results['total_failed']}")
    print(f"Total Successful Logins : {results['total_success']}")

    print("\n[2] SUSPICIOUS IP ADDRESSES")
    print("-" * 30)
    if results['suspicious_ips']:
        for item in results['suspicious_ips']:
            print(f"IP Address: {item['ip']}  |  Failed Attempts: {item['failed_attempts']}")
    else:
        print("No suspicious IPs found.")

    print("\n[3] SUCCESSFUL LOGIN AFTER MULTIPLE FAILURES")
    print("-" * 45)
    if results['success_after_fail']:
        for item in results['success_after_fail']:
            print(f"IP Address: {item['ip']}  |  Username: {item['username']}  |  Failures Before Success: {item['failed_attempts_before_success']}")
    else:
        print("No successful login after repeated failures detected.")

    print("\n[4] MOST TARGETED USERNAMES")
    print("-" * 30)
    sorted_users = sorted(results['failed_attempts_by_user'].items(), key=lambda x: x[1], reverse=True)

    for username, count in sorted_users[:5]:
        print(f"Username: {username}  |  Failed Attempts: {count}")

    print("\n[5] ATTACK ANALYSIS CONCLUSION")
    print("-" * 30)
    if len(results['suspicious_ips']) > 0:
        print("Possible brute force attack activity detected.")
        print(f"Number of suspicious IPs detected: {len(results['suspicious_ips'])}")
    else:
        print("No major brute force attack pattern detected.")

    print("\n" + "=" * 65)



def save_report(results):
    with open("report.txt", "w") as file:
        file.write("=" * 65 + "\n")
        file.write("BRUTE FORCE ATTACK INVESTIGATION USING AUTHENTICATION LOGS\n")
        file.write("=" * 65 + "\n\n")

        file.write("[1] OVERALL LOG SUMMARY\n")
        file.write("-" * 30 + "\n")
        file.write(f"Total Log Entries       : {results['total_logs']}\n")
        file.write(f"Total Failed Logins     : {results['total_failed']}\n")
        file.write(f"Total Successful Logins : {results['total_success']}\n\n")

        file.write("[2] SUSPICIOUS IP ADDRESSES\n")
        file.write("-" * 30 + "\n")
        if results['suspicious_ips']:
            for item in results['suspicious_ips']:
                file.write(f"IP Address: {item['ip']}  |  Failed Attempts: {item['failed_attempts']}\n")
        else:
            file.write("No suspicious IPs found.\n")

        file.write("\n[3] SUCCESSFUL LOGIN AFTER MULTIPLE FAILURES\n")
        file.write("-" * 45 + "\n")
        if results['success_after_fail']:
            for item in results['success_after_fail']:
                file.write(f"IP Address: {item['ip']}  |  Username: {item['username']}  |  Failures Before Success: {item['failed_attempts_before_success']}\n")
        else:
            file.write("No successful login after repeated failures detected.\n")

        file.write("\n[4] MOST TARGETED USERNAMES\n")
        file.write("-" * 30 + "\n")
        sorted_users = sorted(results['failed_attempts_by_user'].items(), key=lambda x: x[1], reverse=True)
        for username, count in sorted_users[:5]:
            file.write(f"Username: {username}  |  Failed Attempts: {count}\n")

        file.write("\n[5] ATTACK ANALYSIS CONCLUSION\n")
        file.write("-" * 30 + "\n")
        if len(results['suspicious_ips']) > 0:
            file.write("Possible brute force attack activity detected.\n")
            file.write(f"Number of suspicious IPs detected: {len(results['suspicious_ips'])}\n")
        else:
            file.write("No major brute force attack pattern detected.\n")

        file.write("\n" + "=" * 65 + "\n")



def main():
    file_path = "logs/auth.log"

    print("[+] Reading authentication log file...")
    log_entries = parse_log(file_path)

    print("[+] Analyzing logs for brute force attack patterns...")
    results = analyze_logs(log_entries)

    display_results(results)
    save_report(results)

    print("\n[+] Report has been saved as 'report.txt'")


if __name__ == "__main__":
    main()