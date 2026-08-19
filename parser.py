import re
import sys
import os

def parse_log_line(line):
    regex = r"^(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    
    match = re.search(regex, line)
    if match:
        return match.groupdict()
    return None

def main():
    log_path = "logs/auth.log"
    
    if not os.path.exists(log_path):
        print(f"[!] Arquivo de log nao encontrado: {log_path}")
        sys.exit(1)
        
    print("-" * 65)
    print("  LOG PARSER - EXTRACAO DE EVENTOS SSH")
    print("-" * 65)
    
    with open(log_path, "r", encoding="utf-8") as file:
        for line in file:
            parsed_data = parse_log_line(line)
            if parsed_data:
                print(f"[*] Evento: {parsed_data['status']:<8} | User: {parsed_data['user']:<10} | IP: {parsed_data['ip']}")

if __name__ == "__main__":
    main()