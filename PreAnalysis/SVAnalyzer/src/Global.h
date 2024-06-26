#ifndef _GLOBAL_H
#define _GLOBAL_H

#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Support/CommandLine.h"
#include <fstream>
#include <iostream>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "Common.h"
#include "StructAnalyzer.h"

typedef std::vector< std::pair<llvm::Module*, llvm::StringRef> > ModuleList;
typedef std::unordered_map<llvm::Module*, llvm::StringRef> ModuleMap;
typedef std::unordered_map<std::string, llvm::Function*> FuncMap;
typedef std::unordered_map<std::string, llvm::GlobalVariable*> GObjMap;
// Mapping from function name to function.
typedef unordered_map<string, llvm::Function *> NameFuncMap;
typedef llvm::SmallPtrSet<llvm::CallInst*, 8> CallInstSet;
typedef llvm::SmallPtrSet<llvm::Function*, 8> FuncSet;
typedef llvm::SmallPtrSet<llvm::Loop *, 8> LoopSet;
typedef std::unordered_map<std::string, FuncSet> FuncPtrMap;

typedef llvm::DenseMap<llvm::Function*, CallInstSet> CallerMap;
typedef llvm::DenseMap<llvm::CallInst*, FuncSet> CalleeMap;

// add by yx 2018
// if not use, delete it
typedef std::multimap<std::string, std::vector<std::string>> stringMap;
typedef std::map<std::string, std::set<std::string>> stringsetMap;
typedef std::vector<std::string> strvec;
typedef std::set<std::string> strset;

// add by qss 2020
// typedef std::set<llvm::Instruction *> InstSet;
typedef std::map<std::string, llvm::Instruction *> IdInstMap;
// typedef std::set<Loop *> LoopSet;
// typedef std::map<std::string, IdInstMap> 
typedef std::map<int64_t, int32_t> CountMap;
typedef std::map<std::string, CountMap> VarMap;

class GlobalContext {
private:
	// pass specific data
	std::map<std::string, void*> PassData;

public:
	bool add(std::string name, void* data) {
		if (PassData.find(name) != PassData.end())
			return false;

		PassData[name] = data;
		return true;
	}

	void* get(std::string name) {
		std::map<std::string, void*>::iterator itr;

		itr = PassData.find(name);
		if (itr != PassData.end())
			return itr->second;
		else
			return nullptr;
	}

	// StructAnalyzer
	StructAnalyzer structAnalyzer;

	// Map global object name to object definition
	GObjMap Gobjs;

	// Map global function name to function defination
	FuncMap Funcs;

	// Map function pointers (IDs) to possible assignments
	FuncPtrMap FuncPtrs;

	// functions whose addresses are taken
	FuncSet AddressTakenFuncs;

	// potential target loops
	LoopSet TargetLoops;

	Loop* TargetLoop;
	
	// Map a callsite to all potential callee functions.
	CalleeMap Callees;

	// Map a function to all potential caller instructions.
	CallerMap Callers;

	// Map global function name to function.
	NameFuncMap GlobalFuncs;

	// Indirect call instructions.
	std::vector<CallInst *> IndirectCallInsts;

	// Unified functions -- no redundant inline functions
	DenseMap<size_t, Function *> UnifiedFuncMap;
	set<Function *> UnifiedFuncSet;

	// Map function signature to functions
	DenseMap<size_t, FuncSet> sigFuncsMap;

	ModuleList Modules;

	ModuleMap ModuleMaps;
	std::set<std::string> InvolvedModules;
};

class IterativeModulePass {
protected:
	GlobalContext *Ctx;
	const char *ID;
public:
	IterativeModulePass(GlobalContext *Ctx_, const char *ID_)
		: Ctx(Ctx_), ID(ID_) { }

	// run on each module before iterative pass
	virtual bool doInitialization(llvm::Module *M)
		{ return true; }

	// run on each module after iterative pass
	virtual bool doFinalization(llvm::Module *M)
		{ return true; }

	// iterative pass
	virtual bool doModulePass(llvm::Module *M)
		{ return false; }

	virtual void run(ModuleList &modules);
};

#endif
