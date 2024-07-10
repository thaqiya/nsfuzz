#! /bin/bash

set -x

mkdir -p state_variable
mkdir -p sync_point
mkdir -p analysis_time

echo "Processing bftpd..."
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path /magma_run/bftpd --sut_option "-D -c /magma_run/basic.conf" --port 2100
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../state_variable/bftpd -s ../sync_point/bftpd --dump-call-map > output_bftpd 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../analysis_time/bftpd

