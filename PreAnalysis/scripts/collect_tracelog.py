import subprocess
import argparse
import os
import re
import time
import sys
# e.g. usage: python3 collect_tracelog.py -r /home/ubuntu/aflnet/aflnet-replay -c /home/ubuntu/aflnet/bftpd/out_ori/replayable-queue/ --protocol FTP --port 21 -s /home/ubuntu/aflnet/bftpd/bftpd --sut_option "-D -c /home/ubuntu/aflnet/bftpd/bftpd.conf" --pin_path /home/ubuntu/pin-3.18-98332-gaebd7b1e6-gcc-linux/pin

# proftpd: python3 collect_tracelog.py -r /home/ubuntu/aflnet/aflnet-replay -c /home/ubuntu/probenchmark/FTP/proftpd/out_ori/replayable-queue/ --protocol FTP --port 21 -s /home/ubuntu/probenchmark/FTP/proftpd/proftpd --sut_option "-n -c /home/ubuntu/probenchmark/FTP/proftpd/basic.conf -X" --pin_path /home/ubuntu/pin-3.18-98332-gaebd7b1e6-gcc-linux/pin -t ./result/proftpd_tracelog/trace.out --timeout 3000 --init_time 15 --wait

# live555: python3 collect_tracelog.py -r /home/ubuntu/aflnet/aflnet-replay -c /home/ubuntu/probenchmark/RTSP/live555/out_ori/replayable-queue/ --protocol RTSP --port 8554 -s /home/ubuntu/probenchmark/RTSP/live555/testProgs/testOnDemandRTSPServer --sut_option "8554" --pin_path /home/ubuntu/pin-3.18-98332-gaebd7b1e6-gcc-linux/pin -t ./result/live555_tracelog/trace.out --timeout 500 --init_time 5

class PinSUT(object):
    def __init__(self, sut_path, sut_option, pin_path, tracelog_path, wait_flag):
        self.sut_path = sut_path
        self.sut_option = sut_option
        self.pin_path = pin_path
        self.tracelog_path = tracelog_path
        self.wait_flag = wait_flag
        self.args = []

        self._setup_sut()

        self.process = None

    def _setup_sut(self):
        self.args.append(self.pin_path)
        self.args.append("-t")
        self.args.append("../AddrTracer/obj-intel64/AddrTracer.so")
        self.args.append("-o")
        self.args.append(self.tracelog_path)
        dir_path = os.path.dirname(self.tracelog_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        self.args.append("--")
        self.args.append(self.sut_path)
        if self.sut_option is not None:
            self.args.extend(self.sut_option.split(" "))

    def start(self):
        print(" ".join(self.args))
        self.process = subprocess.Popen(self.args)

    def stop(self):
        if self.process != None:
            if self.wait_flag:
                print("--wait enabled, wait server to terminated it self...", end='', flush=True)
                self.process.wait()
                print("Done")
            else:
                time.sleep(1)
                self.process.kill()

class Replayer(object):
    def __init__(self, replayer_path, queue_path, protocol, port, timeout):
        self.replayer_path = replayer_path
        self.queue_path = queue_path
        self.protocol = protocol
        self.port = port
        self.timeout = timeout
        self.args = []

        self._setup_replayer()
        self.process = None

    def _setup_replayer(self):
        self.args.append(self.replayer_path)
        self.args.append(self.queue_path)
        self.args.append(self.protocol)
        self.args.append(self.port)
        self.args.append(self.timeout)

    def start(self):
        print(" ".join(self.args))
        self.process = subprocess.Popen(self.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def get_packet_num(self):
        if self.process == None:
            print("replayer process is not started")
            return
        print("get replayer output")
        outs, errs = self.process.communicate()
        errs = errs.decode('utf-8',"ignore")
        num = re.findall(r"Size of the current packet (\d+)", errs)
        return num[-1]

    def stop(self):
        if self.process != None:
            self.process.kill()



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Collect replayable-queue's tracelog to further analysis.")
    parser.add_argument('--replayer_path', '-r', type=str, default='../../aflnet-replayer', help='The path of replayer dir')
    parser.add_argument('--queue_path', '-c', type=str, default='../../id', help='The path of replayable queue')
    parser.add_argument('--protocol', type=str, default='FTP', help='The protocol type')
    parser.add_argument('--port', type=str, default='21', help='The protocol port')
    parser.add_argument('--timeout', type=str, default='100', help='socket timeout(us)')
    parser.add_argument('--init_time', type=str, default='0.5', help='server init time(s)')
    parser.add_argument('--wait', action="store_true", default=False, help='wait server to terminated itself')

    parser.add_argument('--sut_path', '-s', type=str, help='The path of SUT executable')
    parser.add_argument('--sut_option', help='The option of SUT executable')
    parser.add_argument('--pin_path', '-p', type=str ,help='The path of Intal Pin')
    parser.add_argument('--tracelog_path', '-t', type=str, default='./result/tracelog/trace.out', help='The tracelog path genetated by pintools')

    args = parser.parse_args()

    # init pintools .so library
    pin_target = PinSUT(args.sut_path, args.sut_option, args.pin_path, args.tracelog_path, args.wait)
    wait_init_time = float(args.init_time)

    if not os.path.exists(args.queue_path):
        print("queue path not exists!")
        sys.exit(-1)

    for queue in os.listdir(args.queue_path):
        # init replayer (aflnet-replayer with generated replayable-queue)
        case_id = re.findall(r'(id:\d+)', queue)[0]
        if int(case_id[3:]) > 50:
            continue
        replayer = Replayer(args.replayer_path, os.path.join(args.queue_path, queue), args.protocol, args.port, args.timeout)
        pin_target.start()
        time.sleep(wait_init_time)
        replayer.start()
        case_packet_num = replayer.get_packet_num()
        print("case id: %s, packet num: %s" % (case_id, case_packet_num))
        os.rename(args.tracelog_path, args.tracelog_path.replace('trace.out', case_id + '_trace_' + case_packet_num + '.out'))
        replayer.stop()
        pin_target.stop()
        # exit()
        
        
