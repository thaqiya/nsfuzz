#include <llvm/Pass.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/TypeFinder.h>
#include <llvm/Analysis/Passes.h>
#include <llvm/Analysis/CFG.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringMap.h>

#include "DepAnalysis.h"
#include "CallGraph.h"
#include "Annotation.h"

using namespace llvm;
using namespace std;

#define DALog llvm::errs()
// #define DEBUG 1

extern stringsetMap CallMap;
extern std::map<std::string, int> myCallerCountMap;
extern std::map<std::string, int> myCalleeCountMap;
extern stringsetMap sys_calleemap;
extern strset sys_calleeset;
extern stringsetMap sysLIdMap; 
extern stringsetMap sysSIdMap;
extern std::map<std::string, IdInstMap> sysLInstMap;
extern std::map<std::string, IdInstMap> sysSInstMap;
extern std::string syscaller;
extern stringsetMap depmap;
extern strset LIdset;
extern strset SIdset;
extern std::vector<std::pair<std::string, int>> call_stack;
extern strset sysfunc;
extern stringsetMap LIdMap; 
extern stringsetMap SIdMap;
extern std::map<std::string, IdInstMap> LInstMap;
extern std::map<std::string, IdInstMap> SInstMap;
extern strset DvCandidates;
extern strset SuspicionDvCandidates;
extern int DvConditionBranches;
extern strset globalSIdSet;
extern strset DepValSet;


void printTypeRecursive(Type *targetType, bool first, std::vector<std::string> &tyVec) {
    bool hasStructElement;

    hasStructElement = false;

    std::string type_str;
    llvm::raw_string_ostream rso(type_str);
    targetType->print(rso);
    std::vector<std::string>::iterator tyVec_iter;
    tyVec_iter = std::find(tyVec.begin(), tyVec.end(), rso.str());
    if ( tyVec_iter != tyVec.end()) {
        DALog << "Dup when handleTypeRecursive for type " << rso.str() << "\n";
        return;
    } else {
        DALog << "handleTypeRecursive for type " << rso.str() << "\n";
    }
    if (!first && targetType->isPointerTy()) {
#ifdef DEBUG
        DALog << "!first && targetType->isPointerTy(), return\n";
#endif
      return;
    }
    if (targetType->isPointerTy()) {
#ifdef DEBUG
        DALog << "strip pointer\n";
#endif
        printTypeRecursive(targetType->getContainedType(0), true, tyVec);
    }
    if(targetType->isStructTy()) {
        StructType * STy = dyn_cast<StructType>(targetType);
        if (STy == nullptr || (STy->isLiteral()) || !(STy->hasName()) || targetType->getStructName().empty()) {
#ifdef DEBUG
                DALog << "STy == nullptr || !(STy->isLiteral()) || !(STy->hasName()) || targetType->getStructName().empty()\n";
                DALog <<  (STy == nullptr) << " || " << (STy->isLiteral()) << " || " << !(STy->hasName()) << " || " << targetType->getStructName().empty() << "\n";
#endif
            return;
        }
        string src_st_name = targetType->getStructName().str();
        if(src_st_name.find(".anon") != string::npos) {
            // OK, this is anonymous struct or union.
            DALog << *targetType << "\n";
            for(unsigned int curr_no=0; curr_no<targetType->getStructNumElements(); curr_no++) {
                // print by adding space
#ifdef DEBUG
                DALog << "getStructNumElements: \n";
                DALog << *(targetType->getStructElementType(curr_no)) << "\n";
#endif
                printTypeRecursive(targetType->getStructElementType(curr_no), false, tyVec);
            }
        }
        else {
            // for regular structure, we also print it's elements' types recursively
            DALog << *targetType << "\n";
            for(unsigned int curr_no=0; curr_no<targetType->getStructNumElements(); curr_no++) {
                // print by adding space
#ifdef DEBUG
                DALog << "getStructNumElements: \n";
                DALog << *(targetType->getStructElementType(curr_no)) << "\n";
#endif
                if (targetType->getStructElementType(curr_no)->isStructTy() || 
                  isa<ArrayType>(targetType->getStructElementType(curr_no))) {
                    hasStructElement = true;
                    break;
                }
            }
            if (hasStructElement)
            {
                for (unsigned int curr_no = 0;
                     curr_no < targetType->getStructNumElements();
                     curr_no++) {
                    // print by adding space
                    if (targetType->getStructElementType(curr_no)
                          ->isStructTy())
                        printTypeRecursive(targetType->getStructElementType(curr_no), false, tyVec);
                    else if (ArrayType *AT = dyn_cast<ArrayType>(targetType->getStructElementType(curr_no)))
                    {
#ifdef DEBUG
                        DALog << "ArrayType: " << *AT << "\n";
#endif
                        printTypeRecursive(targetType->getStructElementType(curr_no), false, tyVec);
                    }
                }
            }
        }
        // Regular structure, print normally.
        DALog << *targetType << "\n";
        for (unsigned int curr_no = 0;
          curr_no < targetType->getStructNumElements(); curr_no++) {
            if (targetType->getStructElementType(curr_no)->isStructTy())
                continue;
            string SId;
            SId = src_st_name + ",0," + to_string(curr_no);
            // if (dv_black_list.count(SId) != 0)
            //     continue;
            DALog << "[+] Found Id: " << SId << " | Load pointer value: unknown " << "| Type: " << *(targetType->getStructElementType(curr_no)) << "\n";
            SIdset.insert(SId);
#ifdef DEBUG
            DALog << "SIdset length: " << SIdset.size() << "\n";
#endif
        }
        DALog << "End memcpy call\n";
        tyVec.push_back(rso.str());
    }
}


// dump callmap
void dumpCallMap() {
	ofstream CallMapfile;
	CallMapfile.open("./result/CallMap.txt");
	CallMapfile << CallMap.size() << "\n";
	for (auto &l : CallMap) {
		CallMapfile << l.first << ":" << l.second.size() << "\n";
		for (auto &id : l.second)
        {
			CallMapfile << id << " ; ";
        }
		CallMapfile << "\n";
	}
	CallMapfile.close();
}


// travel callgraph recursively
void circle_callee(std::string caller, int layer){
    if (layer > MAXCALLDEPTH) return;
    if(CallMap.count(caller) != 0){
		for(auto &f : CallMap[caller])
        {
            if (f == "send_cmd_from_kernel")
                continue;
			if (sys_calleeset.count(f) == 0 && f != syscaller)
            {
                if (myCallerCountMap.count(f) == 0 || myCallerCountMap[f] < MAXREF)
                {
                    if (myCalleeCountMap.count(f) == 0 || myCalleeCountMap[f] < MAXCALLNUM)
                    {
#ifdef DEBUG
                        DALog << "Caller:" << caller << "< MAXREF, insert Callee: " << f << ": ";
                        if (myCallerCountMap.count(f) != 0)
                            DALog << myCallerCountMap[f] <<"\n";
                        else
                            DALog << "\n";
                        DALog << "Caller:" << caller << "< MAXCALLNUM, insert Callee: " << f << ": ";
                        if (myCalleeCountMap.count(f) != 0)
                            DALog << myCalleeCountMap[f] <<"\n";
                        else
                            DALog << "\n";
#endif
				    sys_calleeset.insert(f);
                    call_stack.push_back({f, layer});
                    circle_callee(f, layer+1);
                    }
                }
            #ifdef DEBUG
                else
                {
                    DALog << ">= MAXREF, not insert Callee: " << f << ": " << myCallerCountMap[f] << "\n";
                    DALog << ">= MAXCALLNUM, not insert Callee: " << f << ": " << myCalleeCountMap[f] << "\n";
                }
            #endif
		    }
        }
	}
}

// tool function, just like str.split in python
std::vector<std::string> split(std::string str,std::string pattern)
{
    #ifdef DEBUG
        DALog << "spliting string: " << str << " with " << pattern << "\n";
    #endif

    std::string::size_type pos;
    std::vector<std::string> result;
    str+=pattern;//扩展字符串以方便操作
    int size=str.size();

    for(int i=0; i<size; i++)
    {
        pos=str.find(pattern,i);
        if(pos<size)
        {
            std::string s=str.substr(i,pos-i);
            result.push_back(s);
            i=pos+pattern.size()-1;
        }
    }
    return result;
}


void printsoureinfo(Instruction *Inst) {
  if (Inst == nullptr) {
      DALog << "[!] printsoureinfo a nullptr!\n";
      return;
  }
  if (DILocation *Loc = Inst->getDebugLoc()) { // Here I is an LLVM instruction
    unsigned Line = Loc->getLine();
    StringRef File = Loc->getFilename();
    StringRef Dir = Loc->getDirectory();
    // bool ImplicitCode = Loc->isImplicitCode();
    DALog << Dir << "/" << File << ": line " << Line << "\n";
  } else
    DALog << "NO MATCHED SOURCE INFO\n";
}

void dumpbcfile() {
  ofstream llbcfile;
  llbcfile.open("./result/llbcfile.txt");
  llbcfile << InputFilenames.size() << "\n";
  for (unsigned i = 0; i < InputFilenames.size(); ++i)
  	llbcfile << InputFilenames[i] << "'\n";
  llbcfile.close();
}


void createdepmap() {
    for (const auto &lm : LIdMap) {
        strset depset;
        for (auto &Lid : lm.second) {
            for (const auto &sm : SIdMap) {
                if (sm.second.count(Lid) != 0) {
                    DALog << "find dep: lm sm " << lm.first << " "<< sm.first <<  " LId-SId: " << Lid << "\n";
                    // DALog << "LoadInst: " << *(LInstMap[lm.first][Lid]) << " source location: ";
                    printsoureinfo(LInstMap[lm.first][Lid]);
                    DALog << "StoreInst source location: ";
                    printsoureinfo(SInstMap[sm.first][Lid]);
                    depset.insert(sm.first);
                    DepValSet.insert(Lid);
                }
            }
        }
        if (depset.size() > 0)
            depmap.insert({lm.first, depset});
    }
}

void dumpdepmap() {
  ofstream depfile;
  depfile.open("./result/depmap.txt");
  int sysc = 0;
  for (auto &deps :depmap) {
  	if (0)
		depfile << " \"" << deps.first << "\": \n[";
	else 
		depfile << " \"" << deps.first << "\":" << deps.second.size() << "\n[";
	int depc = 0;
	for (auto &dep : deps.second) {
		depc++;
		if (depc == 1)
			depfile << "\"" << dep << "\"";
		else 
			depfile << ", \"" << dep << "\"";
	}
	depfile << "]\n";
  }
  depfile.close();
}