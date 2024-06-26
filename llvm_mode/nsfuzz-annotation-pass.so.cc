#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"
#include "Annotation.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fstream>

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

typedef set<string> StringSet;
typedef map<string, s16> GVInitializer;

namespace {

  class NSFuzzAnnotationParse : public ModulePass {

    public:
      static char ID;
      StringSet StateValIDSet;
      StringSet IndexSet;
      int sv_num = 0;
      
      NSFuzzAnnotationParse() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;
      void loadStateVar();
      void dumpStateVar();

  };

}


char NSFuzzAnnotationParse::ID = 0;


bool NSFuzzAnnotationParse::runOnModule(Module &M) {

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "nsfuzz-annotation-pass " cBRI VERSION cRST " parsing state annotation...\n");

  } else be_quiet = 1;
  
  loadStateVar();

  for (auto &F : M) {

    for (auto &BB : F) {

      for (auto &I : BB) {

        // errs() << I << "\n";

        if (StoreInst *S = dyn_cast<StoreInst>(&I)) {

          // errs() << "\nStoreInst: " << *S << "\n";

          // string VariableID = getStoreId(S);

          Value *V = S->getPointerOperand();

          // errs() << "VariableID: " << VariableID << "\n";

          // errs() << "Variable: " << *V << "\n";

          /* Most cases: global variable */
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(V)) {
            
            string VariableID = getStoreId(S);

            // errs() << "Global Variable, id: " << VariableID << "\n";

            for (Module::global_iterator GI = M.global_begin(), GE = M.global_end(); GI != GE; ++GI) {

              if (GI->getName() == "llvm.global.annotations") {

                ConstantArray *CA = dyn_cast<ConstantArray>(GI->getOperand(0));

                for(auto OI = CA->op_begin(); OI != CA->op_end(); ++OI) {
                  
                  ConstantStruct *CS = dyn_cast<ConstantStruct>(OI->get());
                  
                  // errs() << *CS << "\n";

                  GlobalVariable *CGV;

                  if (dyn_cast<GlobalVariable>(CS->getOperand(0))) {
                    
                    CGV = dyn_cast<GlobalVariable>(CS->getOperand(0));// OKF("extract GV: %s\n");

                    // errs() << "extract GV: " << *CS->getOperand(0) << "\n";

                  } else if (dyn_cast<GlobalVariable>(CS->getOperand(0)->getOperand(0))) {

                    CGV = dyn_cast<GlobalVariable>(CS->getOperand(0)->getOperand(0));

                    // errs() << "extract GV: " << *CS->getOperand(0)->getOperand(0) << "\n";

                  } else {

                    FATAL("CAN NOT EXTRACT GV ANNOTATION, CHECK THE BUG!");

                  }

                  GlobalVariable *AnnotationGL = dyn_cast<GlobalVariable>(CS->getOperand(1)->getOperand(0));

                  // errs() << "anno: " << *AnnotationGL << "\n";

                  StringRef annotation = dyn_cast<ConstantDataArray>(AnnotationGL->getInitializer())->getAsCString();

                  // errs() << annotation << "\n";

                  if(annotation.compare("NSFUZZ_STATE") == 0 && GV == CGV) {

                    ACTF("Find annotations");

                    OKF("Global Variable Type, id: %s", VariableID.c_str());

                    if (!StateValIDSet.count(VariableID)) {

                      StateValIDSet.insert(VariableID);

                      sv_num++;

                    }

                    if (ConstantInt *Constval = dyn_cast<llvm::ConstantInt>(GV->getInitializer())) {

                      // OKF("Variable id: %s, init value: %ld", VariableID.c_str(), Constval->getSExtValue());

                      hash<string> hasher;

                      u16 hash_value = hasher(VariableID);

                      ACTF("hash value: %u, store var: %s", hash_value, VariableID.c_str());

                      // string Index = to_string(hash_value ^ s16(Constval->getSExtValue()) + 32768);
                      string Index = to_string(hash_value);

                      OKF("shared memory index: %s, init value: %ld", Index.c_str(), Constval->getSExtValue());

                      Index = Index + "," + to_string(Constval->getSExtValue());

                      if (!IndexSet.count(Index)) {

                          IndexSet.insert(Index);

                      }
                    }
                  }
                }
              }
            }
            continue;
          }

          /* LightFTP case: store <- bitcast <- call
            %73 = call i8* @llvm.ptr.annotation.p0i8(i8* %72, i8* getelementptr inbounds ([13 x i8], [13 x i8]* @.str, i32 0, i32 0), i8* getelementptr inbounds ([12 x i8], [12 x i8]* @.str.1, i32 0, i32 0), i32 91), !dbg !792
            %74 = bitcast i8* %73 to i32*, !dbg !792
            store i32 0, i32* %74, align 4, !dbg !793 */
          if (BitCastInst *BC = dyn_cast<BitCastInst>(V)) {

              // errs() << "Variable used by BitCastInst: " << *BC << "\n";

              V = BC->getOperand(0);

              // errs() << "BastCastVariable: " << *V << "\n";
          }

          /* Normal bftpd case: store <- call
            %18 = call i8* @llvm.ptr.annotation.p0i8(i8* %17, i8* getelementptr inbounds ([13 x i8], [13 x i8]* @.str.6, i32 0, i32 0), i8* getelementptr inbounds ([14 x i8], [14 x i8]* @.str.7, i32 0, i32 0), i32 10), !dbg !226
            store i8 1, i8* %18, align 8, !dbg !228 */
          if (CallInst *C = dyn_cast<CallInst>(V)) {

            // errs() << "Variable used by CallInst: " << *C << "\n";

            if (C->isInlineAsm())
                continue;

            Function *Fun = C->getCalledFunction();

            if (Fun && (Fun->getName().startswith("llvm.ptr.annotation"))) {
              
              // errs() << "Used variable: " << *C->getOperand(0) << "\n";

              string VariableID = getAnnotation(C->getOperand(0), &M);

              ACTF("Find annotations");

              OKF("Struct Member Variable, id: %s\n", VariableID.c_str());

              if (!StateValIDSet.count(VariableID)) {

                  StateValIDSet.insert(VariableID);

                  sv_num++;

              }
            }
          }
        } 
      }
    }
  }

  dumpStateVar();

  /* Say something nice. */

  if (!be_quiet) {

    if (!sv_num) WARNF("No annotated state variable found.");
    else OKF("Found %d state variable for now.", sv_num);

  }

  return true;

}

void NSFuzzAnnotationParse::loadStateVar() {

  ifstream StateVarFile, GVIndexFile;

  StateVarFile.open(DEFAULT_SVLIST_PATH);

  GVIndexFile.open(DEFAULT_GINDEX_PATH);

  string SV;

  while (getline(StateVarFile, SV)) {

    StateValIDSet.insert(SV);

    sv_num++;

  }

  string Index;

  while (getline(GVIndexFile, Index)) {

      IndexSet.insert(Index);

  }

  StateVarFile.close();

  return;
}

void NSFuzzAnnotationParse::dumpStateVar() {

  ofstream StateVarFile, GVIndexFile;

  StateVarFile.open(DEFAULT_SVLIST_PATH);

  GVIndexFile.open(DEFAULT_GINDEX_PATH);

  for (auto InstID : StateValIDSet)
    StateVarFile << InstID << "\n";

  for (auto Index: IndexSet)
    GVIndexFile << Index << "\n";

  StateVarFile.close();
  GVIndexFile.close();

  return;
}

static void registerNSFuzzPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new NSFuzzAnnotationParse());

}


static RegisterStandardPasses RegisterNSFuzzPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerNSFuzzPass);

static RegisterStandardPasses RegisterNSFuzzPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerNSFuzzPass);
