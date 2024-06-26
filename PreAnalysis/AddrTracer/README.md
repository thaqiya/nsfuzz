## AddrTracer

AddrTracer is a pintool to trace the stateful server, for finding a proper sync point to instrument raise(STGSTOP);

## Download

Downlaod [Intel Pin](https://software.intel.com/content/www/us/en/develop/articles/pin-a-binary-instrumentation-tool-downloads.html)

## Compile

Extract the Pin, and specifiy the path as PIN_ROOT (for me, its /home/ubuntu/pin-3.18-98332-gaebd7b1e6-gcc-linux/), then make AddrTracer.

```
export PIN_ROOT=your-pin-path
export PATH=$PATH:$PIN_ROOT
make obj-intel64/AddrTracer.so
```

## Usage
```
pin -t obj-intel64/AddrTracer.so <-o trace_file> -- target-server <server option>
```

## Testing
1. Compile the pintool-test.c
    ```
    gcc pintool-test.c -o pintool-test
    ```
2. Trace it with AddrTracer
    ```
    pin -t obj-intel64/AddrTracer.so -- ./pintool-test
    ```
3. The generated trace.out content:
    ```
    0x400537      main		push rbp
    0x400538      main		mov rbp, rsp
    0x40053b      main		sub rsp, 0x20
    0x40053f      main		mov dword ptr [rbp-0x14], edi
    0x400542      main		mov qword ptr [rbp-0x20], rsi
    0x400546      main		mov edi, 0x4005ff
    0x40054b      main		call 0x400400
    0x400550      main		mov dword ptr [rbp-0x4], 0x1
    0x400557      main		cmp dword ptr [rbp-0x4], 0x0
    0x40055b      main		jz 0x400562
    0x40055d      main		call 0x400526
    0x400526       foo		push rbp
    0x400527       foo		mov rbp, rsp
    0x40052a       foo		mov edi, 0x4005f4
    0x40052f       foo		call 0x400400
    0x400534       foo		nop
    0x400535       foo		pop rbp
    0x400536       foo		ret 
    0x400562      main		mov eax, 0x0
    0x400567      main		leave 
    0x400568      main		ret 
    # $eof
    ```