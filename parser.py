import re
import sys
import os
from collections import defaultdict

def parse_log_line(line):
    regex = r"^(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    
    match = re.search(regex, line)
    if match:
        return match.groupdict()
    return None

def analyze_auth_logs(log_path, threshold=3):
    failed_attempts = defaultdict(list)
    successful_logins = []

    with open(log_path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line)
            if event:
                if event["status"] == "Failed":
                    failed_attempts[event["ip"]].append(event)
                elif event["status"] == "Accepted":
                    successful_logins.append(event)

    brute_force_alerts = {}
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= threshold:
            brute_force_alerts[ip] = attempts

    return {
        "brute_force": brute_force_alerts,
        "successful": successful_logins,
        "total_failed": sum(len(v) for v in failed_attempts.values())
    }

def main():
    log_path = "logs/auth.log"
    
    if not os.path.exists(log_path):
        print(f"[!] Arquivo de log nao encontrado: {log_path}")
        sys.exit(1)
        
    print("-" * 65)
    print("  LOG PARSER - EXTRACAO DE EVENTOS SSH")
    print("-" * 65)
    
    results = analyze_auth_logs(log_path, threshold=3)

    print(f"\n[+] Total de falhas de autenticação mapeadas: {results['total_failed']}")
    print(f"[+] Total de logins bem-sucedidos          : {len(results['successful'])}\n")

    if results["brute_force"]:
        print("[ALERTA CRÍTICO] POTENCIAIS ATAQUES DE FORÇA BRUTA DETECTADOS:")
        for ip, attempts in results["brute_force"].items():
            print(f"  [!] IP Atacante: {ip} | Total de falhas: {len(attempts)}")
            for att in attempts:
                print(f"      - Data/Hora: {att['date']} | Usuário alvo: {att['user']}")
    else:
        print("[OK] Nenhuma atividade suspeita de força bruta detectada.")
        
if __name__ == "__main__":
    main()