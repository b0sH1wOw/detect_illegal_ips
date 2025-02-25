#
# run this script on remote server, ensure that you have permission to run sudo without a password.
# you can run this script with nohup, for example:
# nohup python detect_illegal_ips.py > illegal_ips.log 2>&1 &
#
from config import (
    route_method_rules,
    nginx_log_path,
    nginx_log_pattern,
    white_list,
    illegal_number_threshold,
    illegal_rate_threshold,
    iptables_rules_path
)

import re
import subprocess
import time


def ip_exists_in_iptables(ip_address: str) -> bool:
    try:
        output = subprocess.check_output(['sudo', 'iptables', '-L', '-n'], text=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running iptables: {e}")
        return False

    return ip_address in output


def add_illegal_ip_to_iptables(ip_address: str) -> None:
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)

        with open(iptables_rules_path, 'w') as f:
            subprocess.run(['sudo', 'iptables-save'], stdout=f, check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while adding IP to iptables: {e}")


def detect_illegal_ips() -> list[tuple[str, dict[str, int]]]:
    def calc_illegal_rate(ip: str, dic: dict[str, int]) -> float:
        return dic[ip]['illegal'] / (dic[ip]['legal'] + dic[ip]['illegal'])
    
    def parse_nginx_log() -> dict[str, dict[str, int]]:
        dic = {}

        with open(nginx_log_path, 'r') as f:
            for line in f:
                matched = re.match(nginx_log_pattern, line)

                if matched:
                    ip = matched.group(1)
                    others = matched.group(2)

                    if ip not in dic:
                        dic[ip] = {'legal': 0, 'illegal': 0, 'illegal_rate': 0}

                    if ip in white_list:
                        dic[ip]['legal'] += 1
                        dic[ip]['illegal_rate'] = calc_illegal_rate(ip, dic)
                        continue

                    if len(parts := others.split(' ')) > 1:
                        method, path = parts[0], parts[1]
                        route = path.split('?')[0]

                        if route == '/':
                            continue

                        if route in route_method_rules:
                            if method in route_method_rules[route]:
                                dic[ip]['legal'] += 1
                            else:
                                dic[ip]['illegal'] += 1
                        else:
                            dic[ip]['illegal'] += 1
                    else:
                        dic[ip]['illegal'] += 1

                    dic[ip]['illegal_rate'] = calc_illegal_rate(ip, dic)

        return dic

    dic = parse_nginx_log()
    results = []

    for k, v in dic.items():
        if v['illegal_rate'] >= illegal_rate_threshold and \
            v['illegal'] >= illegal_number_threshold: 
            results.append((k, v))

    return results
    

if __name__ == '__main__':
    while True:
        for ip, data in detect_illegal_ips():
            if ip_exists_in_iptables(ip):
                continue

            add_illegal_ip_to_iptables(ip)
            print((
                f'Added {ip}\tIllegal rate: {data["illegal_rate"]}\t'
                f'({data["legal"]} legal, {data["illegal"]} illegal)'
            ))

        time.sleep(60)
