import gdb
import os
import re

def callGdb(cmd):
    return gdb.execute(cmd, to_string=True).splitlines()

def start(sut):
    read_bp = "b read"
    if sut == "sshd":
        read_bp += " if compat20==1"
    callGdb(read_bp)
    callGdb("b fgets")
    callGdb("b recv")
    callGdb("b recvmsg")
    callGdb("b recvfrom")
    callGdb("continue")
    bt_info = callGdb("bt")
    print(bt_info)
    btrace_info = ""
    first = True
    for line in bt_info:
        if re.search(r'#\d+.*\s(.*)\s\(.*\).*', line):
            funcname = re.findall(r'#\d+.*\s(.*)\s\(.*\).*', line)[0]
            if first:
                btrace_info = funcname
                first = False
            else:
                btrace_info = funcname + "->" + btrace_info
    
    print(btrace_info)
    with open("./input.btrace", 'w') as file:
        file.write(btrace_info + "\n")
    callGdb("quit")

if __name__ == "__main__":
    sut = os.environ.get('SUT')
    start(sut)