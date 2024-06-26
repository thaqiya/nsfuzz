CC=~/AFL/afl-clang-fast make clean all
ps -ef | grep bftpd | awk '{print "sudo kill -9 "$2}' | sh