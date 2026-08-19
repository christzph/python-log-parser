# LOG PARSER & SIEM BÁSICO
Analisador de Logs SSH e Detecção de Ataques de Força Bruta

---

## 1. INFORMAÇÕES DO SISTEMA
- Linguagem: Python 3.x
- Módulos: re (Regex), argparse, os, sys, collections
- Foco: Blue Team, SOC (Security Operations Center), Correlação de Eventos

---

## 2. VISÃO GERAL
Ferramenta de linha de comando (CLI) desenvolvida em Python para atuar como um SIEM (Security Information and Event Management) básico. O script faz a ingestão de logs de autenticação do Linux (`auth.log`), extrai metadados utilizando Expressões Regulares (Regex) e correlaciona eventos para detectar potenciais ataques de Força Bruta (Brute Force) em serviços SSH.

---

## 3. RECURSOS IMPLEMENTADOS
- **Motor de Extração (Regex):** Varredura de logs estruturados e não estruturados para isolar Data, Hora, Status, Usuário e IP de origem.
- **Correlação de Eventos:** Agrupamento de falhas de autenticação com base no endereço IP do atacante.
- **Limites Dinâmicos (Threshold):** Parâmetros customizáveis via CLI para definir o limite de tolerância de falhas antes de disparar um alerta crítico.
- **Relatório de Auditoria:** Exibição clara e formatada de logins bem-sucedidos e detalhamento de ataques detectados.

---

## 4. INSTRUÇÕES DE USO

Clone o repositório:
```bash
git clone [https://github.com/christzph/python-log-parser.git](https://github.com/christzph/python-log-parser.git)
cd python-log-parser