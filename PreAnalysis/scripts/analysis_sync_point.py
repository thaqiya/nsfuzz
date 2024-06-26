import subprocess
import argparse
import os
import re
import json
import sys

# e.g. usage: python3 analysis_sync_point.py -s ../../bftpd/bftpd
# proftpd: python3 analysis_sync_point.py -s /home/ubuntu/probenchmark/FTP/proftpd/proftpd -t ./result/proftpd_tracelog/
# live555: python3 analysis_sync_point.py -s /home/ubuntu/probenchmark/RTSP/live555/testProgs/testOnDemandRTSPServer -t ./result/live555_tracelog/

# case_info:
# {
#     'case_id' : int
#     'packet_num' : int,
#     'potenial_addr' : { source_info : repeated_times} (the repeated times must be in [0.75 * packet_num, packet_num] )
# }

# global_info:
# {
#     'totel_packet_num' : int,
#     'potenial_addr' : { source_info : repeated_times} (the repeated times must be in [0.75 * totel_packet_num, totel_packet_num])
# }

def get_source_info(addr, sut_path):
    args = []
    args.append('addr2line')
    args.append('-a')
    args.append(addr)
    args.append('-e')
    args.append(sut_path)
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process == None:
        print("addr2line process is not started")
        exit(-1)
    outs, errs = process.communicate()
    outs = outs.decode('utf-8',"ignore").strip()
    # print(outs)
    # print(outs.split('\n')[-1])
    # exit()
    return outs.split('\n')[-1]



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Analysis the tracelog to find sync point.")

    parser.add_argument('--tracelog_path', '-t', type=str, default='./result/tracelog/', help='The tracelog path genetated by pintools')
    parser.add_argument('--sut_path', '-s', type=str, help='The path of SUT executable')
    parser.add_argument('--ratio', '-r', type=float, default=0.75, help='The ratio threshold to filter potential sync pont')

    args = parser.parse_args()
    filter_ratio = args.ratio
    global_info = {}
    global_info['totel_packet_num'] = 0
    global_info['potenial_addr'] = {}

    if not os.path.exists(args.tracelog_path):
        print("tracelog path not exists!")
        sys.exit(-1)

    for log_name in os.listdir(args.tracelog_path):
        case_id = int(re.findall(r'id:(\d+)', log_name)[0])
        packet_num = int(re.findall(r'id:\d+_trace_(\d+)', log_name)[0])
        # if case_id != 0:
        #     continue
        print("Start parsing file: %s..." % log_name, end='', flush = True)
        case_info = {}
        file_path = os.path.join(args.tracelog_path, log_name)
        with open(file_path) as file:
            for line in file:
                addr = line.split()[0]
                if addr in case_info:
                    case_info[addr] += 1
                else:
                     case_info[addr] = 1
        
        addr_set = list(case_info.keys())
        case_info['potenial_addr'] = {}

        for addr in addr_set:
            if case_info[addr] >= (int(packet_num) * filter_ratio) and case_info[addr] <= int(packet_num):
                source_info = get_source_info(addr, args.sut_path)
                if '.h' in source_info:
                    continue
                # if 'main.c:9' not in source_info:
                #     continue
                if source_info in case_info['potenial_addr']:
                    case_info['potenial_addr'][source_info] = max(case_info['potenial_addr'][source_info], case_info[addr])
                else:
                    case_info['potenial_addr'][source_info] = case_info[addr]
            del case_info[addr]

        case_info['case_id'] = case_id
        case_info['packet_num'] = packet_num
        global_info['totel_packet_num'] += packet_num
        for source_info in case_info['potenial_addr']:
            if source_info in global_info['potenial_addr']:
                global_info['potenial_addr'][source_info] += case_info['potenial_addr'][source_info]
            else:
                global_info['potenial_addr'][source_info] = case_info['potenial_addr'][source_info]
        print("Done")
    
    for source_info in list(global_info['potenial_addr']):
        times = global_info['potenial_addr'][source_info]
        if times < (global_info['totel_packet_num'] * filter_ratio):
            del global_info['potenial_addr'][source_info]
    print(global_info)

    
    json_name = os.path.basename(args.sut_path)
    json_name += '_syn_point.json'
    print("Saving as json file (%s) ..." % json_name, end='')
    with open(json_name, 'w') as fout:
        json.dump(global_info, fout)
    print("Done")
        