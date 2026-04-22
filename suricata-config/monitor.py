#! /usr/bin/python3
import pyinotify
import ast
import json
import os
import subprocess
import threading
import time
import sys

log_file = "/var/log/suricata/eve.json"
lua_script_file = "/etc/suricata/rules/script.lua"
reputation_file = "/etc/suricata/iprep/reputation.list"
reputation_history_file = "/etc/suricata/iprep/reputation.json"
ips = "/etc/suricata/suricata.yaml"

last_seem = {}
print("ARGV LEN:", len(sys.argv))
if len(sys.argv) > 1:
    SECONDS = sys.argv[1]
else:
    SECONDS = 5
# Monitorando atualização do arquivo eve.json (onde o suricata grava os logs)
class EventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        if event.pathname == log_file:
            with open(log_file, 'r') as f:
                for line in f:
                    pass
                log_event = json.loads(line)
                if 'alert' in log_event:
                    src_ip = log_event['src_ip']
                    if src_ip:
                        change_reputation(src_ip, -8, f"BAD activity for {src_ip}, downgrading reputation")

def calcSlope(n, values):
    # m = ((n * SUM(x*y)) - (SUM(x) * SUM(y))) / ((n * SUM(x²)) - (SUM(x)²))
    SUMx = sum([i for i in range(n+1)])
    SUMy = sum(values)

    # SUMxy
    SUMxy = 0
    for i in range(n):
        SUMxy += values[i] * (i+1)
    
    # SUMx * SUMy
    SUMxSUMy = SUMx * SUMy

    # SUMx²
    SUMx2 = sum([i*i for i in range(n+1)])

    # SUM²x
    SUM2x = SUMx * SUMx

    m = ((n * SUMxy) - SUMxSUMy) / ((n * SUMx2) - SUM2x)
    return m

def updateRep(ip, rep):
    with open(reputation_history_file, 'r') as file:
        data = json.load(file)
    n = data["window_size"]

    host = [host for host in data["hosts"] if host["ip"] == ip][0]
    
    host["rep_history"] = host["rep_history"][1:] + [rep]
    m = calcSlope(n, host["rep_history"])
    host["m"] = m

    with open(reputation_history_file, 'w') as file:    
        json.dump(data, file, indent=4)
    
    return m

# Atualizando reputação de IPs que tiveram interações mal intencionadas com o Suricata
def change_reputation(ip, value, msg):
    print(time.time())
    print(msg)

    if value < 0:
        last_seem[ip] = time.time()

    with open(reputation_file, 'r+') as f:
        lines = f.readlines()
        for i, line in enumerate(lines):
            if line.startswith(ip):
                category, reputation = line.split(',')[1:]
                
                reputation = int(reputation) + int(value)
                if value < 0: 
                    reputation = max(reputation, 0)
                else:
                    reputation = min(reputation, 127)
                
                m = updateRep(ip, reputation)
                
                category = 1 if (m<1) else 2

                print(f"Category: {category}\nRep: {reputation}\nm: {m}\n")
 
                lines[i]=f"{ip},{category},{reputation}\n"
                break
        f.seek(0)
        f.writelines(lines)
        f.truncate()   

def check_and_upgrade(seconds):
    s = int(seconds)
    while True:
        time.sleep(s)
        now = time.time()

        with open(reputation_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            ip = line.split(',')[0]
            last = last_seem.get(ip, 0)

            if now - last >= s:
                change_reputation(ip, 20, f"No activity for {ip}, upgrading reputation")

wm = pyinotify.WatchManager()
handler = EventHandler()
notifier = pyinotify.Notifier(wm, handler)
wm.add_watch(log_file, pyinotify.IN_MODIFY)

upgrade_thread = threading.Thread(target=check_and_upgrade, args=(SECONDS,), daemon=True)
upgrade_thread.start()

print(f"Monitorando {log_file} para atualizações...")
notifier.loop()
