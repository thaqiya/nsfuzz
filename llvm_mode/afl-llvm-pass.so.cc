/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"
#include "Annotation.h"

#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <llvm/IR/DebugInfo.h>

using namespace llvm;
using namespace std;

/* usage(new):
Set NSFUZZ_TRACE_STATE=1 to perform nsfuzz instrumentation.
  (1) Specify SVList to trace, two option method:
    - set ANALYZER_SVFILE_PATH="sv_list_file_path", when use SVAnalyzer to
extract SV where "sv_list_file_path" is the state variable list output (-o) from
SVAnalyzer.
    - set MANNUAL_STATE=1, when use NSFUZZ_STATE annotation to mark state
variable mannually. (2) Specify sync point, two option method:
    - set ANALYZER_SYNCFILE_PATH="sync_point_file_path", when use SVAnalyzer to
extract sync point where "sync_point_file_path" is the sync point output (-s)
from SVAnalyzer.
    - set MANNUAL_SYNC=1, when use NSFUZZ_SYNC annotation to mark sync point
mannually.

Example (bftpd):

use either:
(1) CC=afl-clang-fast NSFUZZ_TRACE_STATE=1
ANALYZER_SVFILE_PATH="/home/ubuntu/bftpd/static_out"
ANALYZER_SYNCFILE_PATH="/home/ubuntu/bftpd/sync_out" make or: (2)
CC=afl-clang-fast NSFUZZ_TRACE_STATE=1 MANNUAL_STATE=1 MANNUAL_SYNC=1 make to
instrument bftpd

*/

// usage(old): Add param(flags) "-mllvm -SVfile=" when compiling target
// static cl::opt<string> InputFilename("SVfile", cl::desc("Specify input state
// variable list filename"), cl::value_desc{"state variable list filename"});
// cl::init("/tmp/sv_list")
// static cl::opt<string> SyncPointFilename("SyncFile", cl::desc("Specify sync
// point filename"), cl::value_desc{"state sync point filename"});

typedef set<string> StringSet;

namespace {

class AFLCoverage : public ModulePass {

  public:
    static char ID;
    string SVListFilePath;
    string SyncPointFilePath;
    StringSet StateValIDSet;
    string SyncPoint;
    GlobalVariable *AFLStateMapPtr;
	llvm::GlobalVariable *AFLStateRangePtr;
	std::map<int, int> SV2CountMap;
	int sv_cnt;
    int inst_store;
    char mannual_sync, mannual_state;

    AFLCoverage() : ModulePass(ID) {}

    bool runOnModule(Module &M) override;
    void loadStateVar();
    void loadSyncPoint();
    bool runOnFunction(Function &F);
    void InjectTraceForSVList(Function &F,
                              set<pair<StoreInst *, u32>> StoreTraceTargets);
    void InjectSignalRaiseForSyncPoint(Function &F, Instruction *I);

    // StringRef getPassName() const override {
    //  return "American Fuzzy Lop Instrumentation";
    // }
};

} // namespace

char AFLCoverage::ID = 0;

bool AFLCoverage::runOnModule(Module &M) {

    LLVMContext &C = M.getContext();

    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

    /* Show a banner */

    char be_quiet = 0;

    mannual_sync = 0, mannual_state = 0;

    if (getenv("NSFUZZ_TRACE_STATE")) {

        if (!getenv("ANALYZER_SVFILE_PATH") && !getenv("MANNUAL_STATE")) {

            FATAL("State variable list missing, use "
                  "ANALYZER_SVFILE_PATH=\"filename\""
                  "or use MANNUAL_STATE=1 with state annotataion.");

        } else if (getenv("ANALYZER_SVFILE_PATH") && getenv("MANNUAL_STATE")) {

            FATAL("Can not use both ANALYZER_SVFILE_PATH and MANNUAL_STATE at "
                  "the "
                  "same time.");

        } else if (getenv("ANALYZER_SVFILE_PATH")) {

            mannual_state = 0;

            SVListFilePath = getenv("ANALYZER_SVFILE_PATH");

        } else if (getenv("MANNUAL_STATE")) {

            mannual_state = 1;

            SVListFilePath = DEFAULT_SVLIST_PATH;
        }

        if (!getenv("ANALYZER_SYNCFILE_PATH") && !getenv("MANNUAL_SYNC")) {

            FATAL("Sync point missing, use ANALYZER_SYNCFILE_PATH=\"filename\""
                  "or use MANNUAL_SYNC=1 with sync annotataion.");

        } else if (getenv("ANALYZER_SYNCFILE_PATH") && getenv("MANNUAL_SYNC")) {

            FATAL("Can not use both ANALYZER_SYNCFILE_PATH and MANNUAL_SYNC at "
                  "the "
                  "same time.");

        } else if (getenv("ANALYZER_SYNCFILE_PATH")) {

            mannual_sync = 0;

            SyncPointFilePath = getenv("ANALYZER_SYNCFILE_PATH");

        } else if (getenv("MANNUAL_SYNC")) {
            // expand from NSFUZZ_SYNC() macro
            mannual_sync = 1;
        }
    }

    if (isatty(2) && !getenv("AFL_QUIET")) {

        SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST
                  " by <lszekeres@google.com>\n");

    } else
        be_quiet = 1;

    /* Decide instrumentation ratio */

    char *inst_ratio_str = getenv("AFL_INST_RATIO");
    unsigned int inst_ratio = 100;

    if (inst_ratio_str) {

        if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
            inst_ratio > 100)
            FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
    }

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
        GlobalVariable::GeneralDynamicTLSModel, 0, false);

    // add by qss
    if (getenv("NSFUZZ_TRACE_STATE")) {
        AFLStateMapPtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0),
                                            false, GlobalValue::ExternalLinkage,
                                            0, "__afl_area_data_ptr");
		AFLStateRangePtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0),
                                            false, GlobalValue::ExternalLinkage,
                                            0, "__afl_area_sv_range_ptr");

        loadStateVar();
        if (!mannual_sync) {
            loadSyncPoint();
		}
    }

    /* Instrument all the things! */

    int inst_blocks = 0;
    inst_store = 0;

    for (auto &F : M) {
        for (auto &BB : F) {

            BasicBlock::iterator IP = BB.getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));

            if (AFL_R(100) >= inst_ratio)
                continue;

            /* Make up cur_loc */

            unsigned int cur_loc = AFL_R(MAP_SIZE);

            ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

            /* Load prev_loc */

            LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
            PrevLoc->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, None));
            Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

            /* Load SHM pointer */

            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
            MapPtr->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(C, None));
            Value *MapPtrIdx =
                IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

            /* Update bitmap */

            LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, None));
            Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
            IRB.CreateStore(Incr, MapPtrIdx)
                ->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));

            /* Set prev_loc to cur_loc >> 1 */

            StoreInst *Store = IRB.CreateStore(
                ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
            Store->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));

            inst_blocks++;
        }

        if (getenv("NSFUZZ_TRACE_STATE"))
            runOnFunction(F);
    }

    /* Say something nice. */

    if (!be_quiet) {

        if (!inst_blocks)
            WARNF("No instrumentation targets found.");
        else
            OKF("Instrumented %u locations (%s mode, ratio %u%%).", inst_blocks,
                getenv("AFL_HARDEN")
                    ? "hardened"
                    : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
                           ? "ASAN/MSAN"
                           : "non-hardened"),
                inst_ratio);

        if (getenv("NSFUZZ_TRACE_STATE")) {
            if (!inst_store)
                WARNF("No state variable instrumentation targets found.");
            else
                OKF("Instrumented %u state variable store locations",
                    inst_store);
        }
    }

    return true;
}

void AFLCoverage::loadStateVar() {
    ifstream StateVarFile;

    // string SVListFilePath = InputFilename;

    StateVarFile.open(SVListFilePath);

    string SV;
	sv_cnt = 0;
    hash<string> hasher;

    while (getline(StateVarFile, SV)) {
        StateValIDSet.insert(SV);
		u16 hash_value = hasher(SV);
		SV2CountMap[hash_value] = sv_cnt;
		sv_cnt++;
	}

    StateVarFile.close();

    return;
}

void AFLCoverage::loadSyncPoint() {

    ifstream SyncPointFile;

    // string SyncPointFilePath = SyncPointFilename;

    SyncPointFile.open(SyncPointFilePath);

    if (!getline(SyncPointFile, SyncPoint))
        WARNF("Can not read sync point file");

    SyncPointFile.close();

    return;
}

bool AFLCoverage::runOnFunction(Function &F) {

    // SmallVector<Instruction *, 8> CmpTraceTargets;
    // SmallVector<Instruction *, 8> SwitchTraceTargets;

    set<pair<StoreInst *, u32>> StoreTraceTargets;
    Instruction *SignalRaiseSyncPoint = NULL;

    hash<string> hasher;

    for (auto &BB : F) {

        for (auto &I : BB) {

            if (StoreInst *S = dyn_cast<StoreInst>(&I)) {
                // CmpTraceTargets.push_back(&Inst);
                string StoreInstID = getStoreId(S);

                if (StoreInstID.find("ret.llvm.ptr.annotation.") == 0 &&
                    !mannual_state)
                    FATAL(
                        "You may set ANALYZER_SVFILE_PATH and use NSFUZZ_STATE "
                        "annotation in the source code at the same time!"
                        "Use MANNUAL_STATE=1 instead or remove all the "
                        "NSFUZZ_STATE "
                        "annotation.");

                // for debug usage
                // if (StoreInstID.find("var.__afl") == 0) continue;
                // llvm::errs() << StoreInstID << "\n";

                if (StateValIDSet.count(StoreInstID)) {

                    u32 hash_value = hasher(StoreInstID);

                    StoreTraceTargets.insert({S, hash_value});
                }
            }

            if (mannual_sync)
                continue;
            // sync point check
            if (DILocation *Loc = I.getDebugLoc()) {
                unsigned Line = Loc->getLine();
                string File = Loc->getFilename();
                string Dir = Loc->getDirectory();
                string LineOfCode = Dir + "/" + File + ":" + to_string(Line);
                // ACTF("LineOfCode: %s\n", LineOfCode.c_str());
                if (LineOfCode == SyncPoint) {
                    SignalRaiseSyncPoint = &I;
                }
            }
        }
    }

    InjectTraceForSVList(F, StoreTraceTargets);

    if (SignalRaiseSyncPoint && !mannual_sync)
        InjectSignalRaiseForSyncPoint(F, SignalRaiseSyncPoint);

    return true;
}

void AFLCoverage::InjectTraceForSVList(
    Function &F, set<pair<StoreInst *, u32>> StoreTraceTargets) {

    Module *M = F.getParent();

    LLVMContext &C = M->getContext();

    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

    for (auto StorePair : StoreTraceTargets) {
        StoreInst *StoreInst = StorePair.first;
        u16 hash_value = StorePair.second;
        IRBuilder<> IRB(StoreInst);
        // Value *addr = StoreInst->getArgOperand(0);
        Value *StoreVal = StoreInst->getValueOperand();

        // hash SID of StoreInst
        // map {hash[SID]} to bitmap index, i.e. [0, 65535]

        // Int16Ty would lead to an signed int16 cast and reture a negative
        // value, not work.
        ConstantInt *HashVar = ConstantInt::get(Int32Ty, hash_value);

        /* Load SHM pointer */
        LoadInst *DataMapPtr = IRB.CreateLoad(AFLStateMapPtr);
        DataMapPtr->setMetadata(M->getMDKindID("nosanitize"),
                                MDNode::get(C, None));
        ACTF("hash value: %u, store variable id: %s\n", hash_value,
             getStoreId(StoreInst).c_str());

        Value *DataMapPtrIdx = IRB.CreateGEP(DataMapPtr, HashVar);

        /* Update bitmap */

        IRB.CreateStore(StoreVal, DataMapPtrIdx)
            ->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));

        inst_store++;

		auto *sv_range_ptr = IRB.CreateLoad(AFLStateRangePtr);
		sv_range_ptr->setMetadata(M->getMDKindID("nosanitize"),
                                  MDNode::get(C, None));
		auto *add_inst = IRB.CreateAdd(StoreVal,
				ConstantInt::get(Int32Ty, SV2CountMap[hash_value] * (1 << 16)));
		auto *sv_range_ptr_idx = IRB.CreateGEP(sv_range_ptr, add_inst);
		IRB.CreateStore(llvm::ConstantInt::get(Int8Ty, 1), sv_range_ptr_idx)
            ->setMetadata(M->getMDKindID("nosanitize"), MDNode::get(C, None));

        // llvm::errs() << "operand: " << *var << "\n";
        // std::string formats = ", value %d: \n";
        // format_string += formats;
        // Value *format_string_ptr =
        // builder.CreateGlobalStringPtr(format_string); Value *Args[] =
        // {format_string_ptr, var}; builder.SetInsertPoint(&B,
        // ++builder.GetInsertPoint()); builder.CreateCall(func_printf, Args);
    }
}

void AFLCoverage::InjectSignalRaiseForSyncPoint(Function &F, Instruction *I) {
    Module *M = F.getParent();

    LLVMContext &C = M->getContext();

    // Type *VoidTy = Type::getVoidTy(C);
    // IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    // IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IRBuilder<> IRB(I);

#if LLVM_VERSION_MAJOR < 9
    Constant *
#else
    FunctionCallee
#endif
        Raise = M->getOrInsertFunction("raise", Int32Ty, Int32Ty
#if LLVM_VERSION_MAJOR < 5
                                       ,
                                       NULL
#endif
        );
#if LLVM_VERSION_MAJOR < 9
    Function *RaiseFunc = cast<Function>(Raise);
#else
    FunctionCallee RaiseFunc = Raise;
#endif

    std::vector<Value *> args;

    ConstantInt *SigStopAttr = ConstantInt::get(Int32Ty, 19);
    args.push_back(SigStopAttr);
    IRB.CreateCall(RaiseFunc, SigStopAttr);
    OKF("Instrumented raise call at sync point: %s\n", SyncPoint.c_str());
}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

    PM.add(new AFLCoverage());
}

static RegisterStandardPasses
    RegisterAFLPass(PassManagerBuilder::EP_ModuleOptimizerEarly,
                    registerAFLPass);

static RegisterStandardPasses
    RegisterAFLPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                     registerAFLPass);
