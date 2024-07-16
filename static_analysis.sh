#! /bin/bash

set -x

mkdir -p state_variable
mkdir -p sync_point
mkdir -p analysis_time


echo "Processing bftpd..."
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path /magma_run/bftpd --sut_option "-D -c /magma/targets/bftpd/run/basic.conf" --port 2100

start=`date +%s.%N`

sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../state_variable/bftpd -s ../sync_point/bftpd --dump-call-map > output_bftpd 2>&1

end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../analysis_time/bftpd
#!/bin/bash

: '
echo "Processing pure-ftpd..."
cd ${HOME}/pure-ftpd
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path src/pure-ftpd --sut_option "-S 2200" --port 2200
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../state_variable/pure-ftpd -s ../sync_point/pure-ftpd --dump-call-map > output_pure-ftpd 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../analysis_time/pure-ftpd

echo "Processing proftpd..."
cd ${HOME}/proftpd
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path ./proftpd --sut_option "-n -d 5 -c /home/ubuntu/proftpd-basic.conf" --port 21
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../state_variable/proftpd -s ../sync_point/proftpd --dump-call-map > output_proftpd 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../analysis_time/proftpd

echo "Processing dnsmasq..."
cd ${HOME}/dnsmasq
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path src/dnsmasq --port 5353 --type udp
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../state_variable/dnsmasq -s ../sync_point/dnsmasq --dump-call-map > output_dnsmasq 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../analysis_time/dnsmasq

echo "Processing tinydtls..."
cd ${HOME}/tinydtls
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path tests/dtls-server --port 20220 --type udp
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../state_variable/tinydtls -s ../sync_point/tinydtls --dump-call-map > output_tinydtls 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../analysis_time/tinydtls

echo "Processing lightftp..."
cd ${HOME}/LightFTP/Source/Release
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path ./fftp --sut_option "/home/ubuntu/lightftp-fftp.conf 2200" --port 2200
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../../../state_variable/lightftp -s ../../../sync_point/lightftp --dump-call-map > output_lightftp 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../../../analysis_time/lightftp

echo "Processing kamailio..."
cd ${HOME}/kamailio
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path src/kamailio --sut_option "-f /home/ubuntu/kamailio-basic.cfg -L src/modules -Y runtime_dir -n 1 -D -E" --port 5060 --type udp
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../state_variable/kamailio -s ../sync_point/kamailio --dump-call-map > output_kamailio 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../analysis_time/kamailio

echo "Processing openssh..."
cd ${HOME}/openssh
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path ./sshd --sut_option "-d -e -p 2200 -r -f sshd_config" --port 2200
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../state_variable/openssh -s ../sync_point/openssh --dump-call-map > output_openssh 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../analysis_time/openssh

echo "Processing exim..."
cd ${HOME}/exim/src
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path build-Linux-x86_64/exim --sut_option "-bd -d -oX 25 -oP /var/lock/exim.pid" --port 25
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../../state_variable/exim -s ../../sync_point/exim --dump-call-map > output_exim 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../../analysis_time/exim

echo "Processing bftpd..."
cd ${HOME}/bftpd
sudo python3 /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path /magma_run/bftpd --sut_option "-D -c /magma/targets/bftpd/run/basic.conf" --port 2100
start=`date +%s.%N`
sudo /magma_out/fuzzer_repo/PreAnalysis/SVAnalyzer/build/bin/SVAnalyzer @bitcode.list -i input.btrace -o ../state_variable/bftpd -s ../sync_point/bftpd --dump-call-map > output_bftpd 2>&1
end=`date +%s.%N`
runtime=$(echo "$end - $start" | bc -l)
echo $runtime > ../analysis_time/bftpd
'


