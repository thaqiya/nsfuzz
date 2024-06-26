# PreAnalysis


Before starting our fuzzer, first we need to do some pre-analysis on SUT (server-under-test), including:

- Find Sync Point. (the raise(SIGSTOP); instrumentation loc)
- Extract the State Variables. (the variable lists to instrument at compile time)

---

## Find Sync Point with AddrTracer (Intel Pintools)

### 1. Build AddrTracer & AFL

check [here](./AddrTracer/README.md) to download, build and test AddrTracer pintool

### 2. Collect and Analysis tracelog with mutated seeds

Currently, we use pintool to collect the trace from the result of AFLNet (the replayable-queues from output folder)

2.1 Use `scripts/collect_tracelog.py` to collect the tracelog .

2.2 Use `scripts/analysis_sync_poitn.py` to analysis the tracelog to help us to find the potential sync point.

TODO: make a shell script to automate the process.

### 3. Sync Point Instrumentation

Mannually for now

---

## Extract the State Variables with LLVM