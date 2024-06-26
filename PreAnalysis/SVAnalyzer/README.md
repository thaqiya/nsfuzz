## Compile

1. Compile LLVM

2. mkdir build && cd build

3. export LLVM_DIR=~/your-llvm-path/ (`LLVM_DIR=~/llvm-9.0.0.src/build/` on my machien)

4. cmake ../

5. make

---

## Command

### LightFTP

1. generate ftpserv.ll

2. static analysis (under `./build/`)

    ```bin/SVAnalyzer ../../LightFTP/Source/ftpserv.ll --LightFTP --dump-call-map --dump-request-dependency > debug.log 2>&1```

### bftpd
1. generate commands.ll

2. static analysis (under `./build/`)

    ```bin/SVAnalyzer ../../bftpd-5.6/commands.ll --Bftpd --dump-call-map --dump-request-dependency > debug_bftpd.log 2>&1```

### pure-ftpd

1. generate ftpd.ll

   - In `pure-ftp` folder: 

        ```CC=clang ./configure --without-privsep –without-capabilities && make```

   - In `pure-ftp/src` folder:

        ```clang -DHAVE_CONFIG_H -I. -I..   -I/usr/local/include -D_FORTIFY_SOURCE=2 -DCONFDIR=\"/etc\" -DSTATEDIR=\"/var\" -DINCLUDE_IO_WRAPPERS=1 -g -O2 -fPIC -fPIE -fwrapv -fno-strict-aliasing -fno-strict-overflow -fstack-protector-all -Winit-self -Wwrite-strings -Wdiv-by-zero -Wno-unused-command-line-argument -MT libpureftpd_a-ftpd.o -MD -MP -MF .deps/libpureftpd_a-ftpd.Tpo -c -o ftpd.ll `test -f 'ftpd.c' || echo './'`ftpd.c -S -emit-llvm```

2. static analysis (under `./build/`)

    ```bin/SVAnalyzer ../../pure-ftpd-1.0.49/src/ftpd.ll --Pureftpd --dump-call-map --dump-request-dependency > debug_pureftpd.log 2>&1```