#! /usr/bin/python3
script = """
function init (args)
    local needs = {} 
    return needs
end

function match(args)
    if math.random() < {} then
        return 1
    end
    return 0
end
"""

ip_rule = 'alert icmp any any -> any any (msg:"ICMP Echo Request"; itype:8; icode:0; sid:9001001; rev:1;)'

rule = """
drop ip any any -> any any \
(\
msg:"Dropar dinamicamente os pacotes"; \
flow:to_server; \
lua:drop/script_{}rep.lua; \
iprep:src,Down,>,{}; sid:{};)
"""
drop_chance = {
    1: 1.0,
    25: 0.75,
    50: 0.5,
    75: 0.25,
    100: 0.0
}

i = 1

print(ip_rule)
for rep in drop_chance:
    with open(f"/etc/suricata/rules/drop/script_{rep}rep.lua", "w+") as f:
        print(script.format("{}", drop_chance[rep]), file=f)
    print(rule.format(rep, rep, i))
    i += 1
