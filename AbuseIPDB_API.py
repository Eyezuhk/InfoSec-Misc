# Criado por Isaac Fernandes em Abril de 2022
# Updated 24/10/2023, Revisado 12/03/2025
# eyezuhk.com.br
import os
import re
import requests
import json
from typing import Tuple, Optional

API_KEYS = [
    '1', '2', '3', '4', '5'  # Substitua por chaves reais
]
URL = 'https://api.abuseipdb.com/api/v2/check'

def check_abuse(ip: str, verifications: int) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Verifica abuso de um IP usando a API do AbuseIPDB."""
    if not API_KEYS:
        raise ValueError("Nenhuma chave de API configurada.")
    
    # Rotação de chaves, limitando ao tamanho da lista
    key_index = min(verifications // 1000, len(API_KEYS) - 1)
    api_key = API_KEYS[key_index]

    querystring = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': 'yes'}
    headers = {'Accept': 'application/json', 'Key': api_key}

    try:
        response = requests.get(URL, headers=headers, params=querystring, timeout=10)
        response.raise_for_status()
        data = response.json()
        return (
            data.get("data", {}).get("isp"),
            data.get("data", {}).get("countryName"),
            data.get("data", {}).get("abuseConfidenceScore")
        )
    except requests.RequestException as e:
        print(f"Erro ao verificar IP {ip}: {e}")
        return None, None, None

def read_ips_from_file(filename: str) -> list[str]:
    """Lê IPs de um arquivo de texto."""
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Erro: Arquivo '{filename}' não encontrado.")
        return []

if __name__ == "__main__":
    filename = 'ips.txt'
    ips_to_check = read_ips_from_file(filename)
    
    if not ips_to_check:
        print("Nenhum IP para verificar. Encerrando.")
        exit(1)

    total_ips = len(ips_to_check)
    checked_ips = 0
    verifications = 0
    
    with open('Reputation.txt', 'w', encoding='utf-8') as saida_file:
        for ip in ips_to_check:
            isp, country_name, abuse_score = check_abuse(ip, verifications)
            output = (
                f'IP: {ip}\n'
                f'ISP: {isp or "Desconhecido"}\n'
                f'Country: {country_name or "Desconhecido"}\n'
                f'ConfidenceScore: {abuse_score if abuse_score is not None else "N/A"}\n\n'
            )
            print(output)
            saida_file.write(output)
            checked_ips += 1
            verifications += 1
        
        summary = f'IPs verificados: {checked_ips} de {total_ips}'
        print(summary)
        saida_file.write(summary)
