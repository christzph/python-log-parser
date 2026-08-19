import argparse
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
    parser = argparse.ArgumentParser(
        description="Log Parser & SIEM Basico - Analisador de Logs SSH"
    )
    
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Caminho para o arquivo de log a ser analisado"
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=3,
        help="Limite de falhas para considerar Forca Bruta (padrao: 3)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] Erro: Arquivo de log nao encontrado: {args.file}")
        sys.exit(1)
        
    print("=" * 65)
    print("  LOG PARSER & SIEM BÁSICO - DETECÇÃO DE FORÇA BRUTA")
    print("=" * 65)
    
    # Executa a analise com os parametros passados via CLI
    results = analyze_auth_logs(args.file, threshold=args.threshold)

    print(f"\n[+] Total de falhas de autenticação mapeadas: {results['total_failed']}")
    print(f"[+] Total de logins bem-sucedidos          : {len(results['successful'])}\n")

    if results["brute_force"]:
        print(f"[ALERTA CRÍTICO] POTENCIAIS ATAQUES DE FORÇA BRUTA (>= {args.threshold} falhas):")
        for ip, attempts in results["brute_force"].items():
            print(f"  [!] IP Atacante: {ip} | Total de falhas: {len(attempts)}")
            for att in attempts:
                print(f"      - Data/Hora: {att['date']} | Usuário alvo: {att['user']}")
    else:
        print("[OK] Nenhuma atividade suspeita de força bruta detectada.")

if __name__ == "__main__":
    main()