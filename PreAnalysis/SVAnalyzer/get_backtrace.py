import subprocess
import argparse
import os
import time
import socket
import sys

# e.g. usage
# bftpd: python3 /home/ubuntu/aflnet/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path ./bftpd --sut_option "-D -c basic.conf" --port 2200
# pure-ftpd: python3 /home/ubuntu/aflnet/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path src/pure-ftpd --sut_option "-S 2200" --port 2200
# proftpd: python3 /home/ubuntu/aflnet/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path ./proftpd --sut_option "-n -d 5 -c /home/ubuntu/proftpd-1.3.6b/basic.conf" --port 2200
# dnsmasq: python3 /home/ubuntu/aflnet/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path src/dnsmasq --port 5353 --type udp
# tinydtls: python3 /home/ubuntu/aflnet/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path tests/dtls-server --port 20220 --type udp
# lightftp: python3 /home/ubuntu/aflnet/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path ./fftp --sut_option "fftp.conf 2200" --port 2200
# kamailio: python3 /home/ubuntu/aflnet/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path src/kamailio --sut_option "-f /home/ubuntu/probenchmark/SIP/kamailio-basic.cfg -L src/modules -Y runtime_dir -n 1 -D -E" --port 5060 --type udp
# exim: python3 /home/ubuntu/aflnet/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path build-Linux-x86_64/exim --sut_option "-bd -d -oX 25 -oP /var/lock/exim.pid" --port 25
# sshd: python3 /home/ubuntu/aflnet/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path ./sshd --sut_option "-d -e -p 2200 -r -f sshd_config" --port 2200

class SUT(object):
    def __init__(self, sut_path, sut_option):
        self.sut_path = sut_path
        self.sut_option = sut_option
        self.name = os.path.basename(sut_path)
        self.args = []
        self._setup_sut()

        self.process = None

    def _setup_sut(self):
        self.args.append(self.sut_path)
        if self.sut_option is not None:
            self.args.extend(self.sut_option.split(" "))

    def start(self):
        print(" ".join(self.args))
        self.process = subprocess.Popen(self.args)

    def get_pid(self):
        if self.process != None:
            return self.process.pid
        return None

    def stop(self):
        if self.process != None:
            self.process.kill()

class GDB(object):
    def __init__(self, target_pid):
        self.target_pid = target_pid
        self.args = []

        self._setup_gdb()
        self.process = None

    def _setup_gdb(self):
        self.args.append("gdb")
        self.args.append("attach")
        self.args.append(str(self.target_pid))
        self.args.append("-x")
        self.args.append(os.path.abspath(os.path.join(sys.argv[0], "..", "GetInputBtrace.py")))

    def start(self):
        print(" ".join(self.args))
        self.process = subprocess.Popen(self.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def stop(self):
        if self.process != None:
            self.process.kill()



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Test the SUT to extract the input backtrace")
    parser.add_argument('--sut_path', '-s', type=str, help='The path of SUT executable')
    parser.add_argument('--sut_option', help='The option of SUT executable')
    parser.add_argument('--port', type=str, default='21', help='The server port')
    parser.add_argument('--type', type=str, default='tcp', help='The socket type')
    args = parser.parse_args()

    # start server under test
    target_sut = SUT(args.sut_path, args.sut_option)
    target_sut.start()
    time.sleep(2)
    os.environ.setdefault('SUT', target_sut.name)

    # establish session
    if args.type == "tcp":
        session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        session.connect(('localhost', int(args.port)))
    elif args.type == "udp":
        session = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        print("Error socket type!")
        target_sut.stop()
        exit(1)
    
    time.sleep(2)

    # start gdb with script
    gdb = GDB(target_sut.get_pid())
    gdb.start()
    time.sleep(2)

    # client send "hello" to trigger gdb breakpoint
    if args.type == "tcp":
        if target_sut.name == "sshd":
            session.send("SSH-2.0-OpenSSH_7.5\n".encode('utf-8'))
            time.sleep(1)
        session.send("hello\r\n".encode('utf-8'))
    elif args.type == "udp":
        session.sendto("hello\r\n".encode('utf-8'), ('127.0.0.1', int(args.port)))
    
    time.sleep(2)
    target_sut.stop()
    session.close()
    gdb.stop()
