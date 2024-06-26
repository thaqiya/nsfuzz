/*
 * main function
 *
 * Copyright (C) 2012 Xi Wang, Haogang Chen, Nickolai Zeldovich
 * Copyright (C) 2015 Byoungyoung Lee
 * Copyright (C) 2015 - 2017 Chengyu Song 
 * Copyright (C) 2016 Kangjie Lu
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
//not int clang8 #include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/SystemUtils.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/Path.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>

#include <memory>
#include <vector>
#include <sstream>
#include <sys/resource.h>

#include "Global.h"
#include "CallGraph.h"
#include "DepAnalysis.h"
#include "Annotation.h"

using namespace llvm;
using namespace std;

// #define DEBUG

// command line parameters definition
cl::list<std::string> InputFilenames(cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));

cl::opt<unsigned> VerboseLevel("htleak-verbose", cl::desc("Print information about actions taken"), cl::init(0));

cl::opt<string> InputBTFilename("i", cl::desc("Specify input backtrace filename"), cl::value_desc("filename"), cl::init("input.btrace"));

cl::opt<string> OutputFilename("o", cl::desc("Specify SV output filename"), cl::value_desc("filename"));

cl::opt<string> SyncPointFilename("s", cl::desc("Specify syncpoint output filename"), cl::value_desc("filename"));

cl::opt<string> SVStartFunc("f", cl::desc("SV scanning start func"), cl::value_desc("funcname"), cl::init("null"));

cl::opt<bool> DumpCallMap("dump-call-map", cl::desc("Dump Call Map"), cl::NotHidden, cl::init(false));

cl::opt<bool> SkipLoopCollect("skip-loop-collect", cl::desc("Skip Loop Collect"), cl::NotHidden, cl::init(false));

GlobalContext GlobalCtx;
string InputBackTrace;
#define Diag llvm::errs()

stringsetMap CallMap;
std::map<std::string, int> myCallerCountMap;
std::map<std::string, int> myCalleeCountMap;
stringsetMap sys_calleemap;
strset sys_calleeset;
stringsetMap sysLIdMap;
stringsetMap sysSIdMap;
std::map<std::string, IdInstMap> sysLInstMap;
std::map<std::string, IdInstMap> sysSInstMap;
std::string syscaller;
stringsetMap depmap;
strset LIdset;
std::map<std::string, int> SvIdMap;
std::map<std::string, int> funcSvLoadMap;
strset SIdset;
std::vector<std::pair<std::string, int>> call_stack;
strset sysfunc;
stringsetMap LIdMap;
stringsetMap SIdMap;
std::map<std::string, IdInstMap> LInstMap;
std::map<std::string, IdInstMap> SInstMap;
int DvConditionBranches = 0;
strset DepValSet;
strset globalSIdSet;
strset gLIdset;
strset gSIdset;
bool dumpCG;


void IterativeModulePass::run(ModuleList &modules) {
  ModuleList::iterator i, e;
  Diag << "[" << ID << "] Initializing " << modules.size() << " modules ";
  bool again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i)
      again |= doInitialization(i->first);
  }

  unsigned iter = 0, changed = 1;
  while (changed) {
    ++iter;
    changed = 0;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      bool ret = doModulePass(i->first);
      if (ret) ++changed;
    }
  }

  again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      // TODO: Dump the results.
      again |= doFinalization(i->first);
    }
  }
}

void doBasicInitialization(Module *M) {
  // struct analysis
  GlobalCtx.structAnalyzer.run(M, &(M->getDataLayout()));
  // collect global object definitions
  for (GlobalVariable &G : M->globals()) {
    if (G.hasExternalLinkage()) {
      GlobalCtx.Gobjs[G.getName()] = &G;
    }
  }
  int fcount = 0;
  // collect global function definitions
  for (Function &F : *M) {
    if (!F.empty()) {
      // external linkage always ends up with the function name
      StringRef FName = F.getName();
#ifdef DEBUG
      Diag << "doBasicInitialization for Function: " << FName << "\n";
#endif
      // loopCollection(M);
      GlobalCtx.Funcs[FName] = &F;
    }
  }
}

void DumpStateVar() {
  ofstream StateValueFile;
  string StateValueFilePath = OutputFilename;
  StateValueFile.open(StateValueFilePath);

  errs() << "\nStateValueFilePath: " << OutputFilename << "\n";

  errs() << "\nDependency Val: " << "\n";

  for (auto InstID : DepValSet)
    StateValueFile << InstID << "\n";
  StateValueFile.close();
  return;
}

void DumpSyncPoint() {
    ofstream SyncPointFile;
    string SyncPointFilePath = SyncPointFilename;
    SyncPointFile.open(SyncPointFilePath);

    errs() << "\nSyncPointFilePath: " << SyncPointFilename << "\n";

    errs() << "\nSyncPoint: "<< "\n";
    errs() << *(GlobalCtx.TargetLoop);

    for (auto &BB : GlobalCtx.TargetLoop->getBlocks()) {
        for (Instruction &I : *BB) {
            if (DILocation *Loc = I.getDebugLoc()) {
                unsigned Line = Loc->getLine();
                string File = Loc->getFilename();
                string Dir = Loc->getDirectory();
                SyncPointFile << Dir << "/" << File << ":" << Line << "\n";
            } else
                SyncPointFile << "Can not get source line info\n";
            break;
        }
        break;
    }
    
    SyncPointFile.close();
    return;
}

int main(int argc, char **argv) {

#ifdef SET_STACK_SIZE
  struct rlimit rl;
  if (getrlimit(RLIMIT_STACK, &rl) == 0) {
    rl.rlim_cur = SET_STACK_SIZE;
    setrlimit(RLIMIT_STACK, &rl);
  }
#endif

  // Print a stack trace if we signal out.
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 9
  sys::PrintStackTraceOnErrorSignal();
#else
  sys::PrintStackTraceOnErrorSignal(StringRef());
#endif
  PrettyStackTraceProgram X(argc, argv);

  llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.

  cl::ParseCommandLineOptions(argc, argv, "global analysis\n");
  SMDiagnostic Err;

  ifstream InputBackTraceFile;
  string InputBackTraceFilePath = InputBTFilename;
  InputBackTraceFile.open(InputBackTraceFilePath);
  getline(InputBackTraceFile, InputBackTrace);
  InputBackTraceFile.close();

  // Loading modules
  Diag << "Total: " << InputFilenames.size() << " file(s)\n\n";
  for (unsigned i = 0; i < InputFilenames.size(); ++i) {
    // Diag << InputFilenames[i] << "\n";
    // use separate LLVMContext to avoid type renaming
    LLVMContext *LLVMCtx = new LLVMContext();
    // parse IR, get module into llvm context
    std::unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);
    if (M == NULL) {
      errs() << argv[0] << ": error loading file '" << InputFilenames[i] << "'\n";
      continue;
    }
    Module *Module = M.release();
    StringRef MName = StringRef(strdup(InputFilenames[i].data()));
    GlobalCtx.Modules.push_back(std::make_pair(Module, MName));
    GlobalCtx.ModuleMaps[Module] = InputFilenames[i];
    doBasicInitialization(Module);
  }
  //erase not syscall function name
  Diag << "\n end for Loading modules \n\n";
  if (DumpCallMap) dumpCG = true;
  // Main workflow
  CallGraphPass CGPass(&GlobalCtx);
  Diag << "\n start for CGPass.run(GlobalCtx.Modules) \n\n";
  CGPass.run(GlobalCtx.Modules);

  // calculate callee
  CallMap = CGPass.dumpCallees();

  if (!SkipLoopCollect)
    CGPass.LoopCollect();

  CGPass.SVCollect(SkipLoopCollect, SVStartFunc);

  createdepmap();
  DumpStateVar();
  if (!SkipLoopCollect)
    DumpSyncPoint();

  errs() << "\nglobalLId size: " << gLIdset.size() << "\n";
  errs() << "\nglobalSId size: " << gSIdset.size() << "\n";

  //dump-call-graph
  if (DumpCallMap){
    dumpCallMap();
    Diag << "Finish dumpCallMap\n";
  }

  return 0;
}
