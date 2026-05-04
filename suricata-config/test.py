import subprocess


subprocess.run('kill -USR2 $(pidof suricata)', shell=True)
