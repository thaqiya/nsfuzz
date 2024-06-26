#ifndef _DEPANALYSIS_H
#define _DEPANALYSIS_H

#include "Global.h"

#define MAXREF 30
#define MAXCALLDEPTH 10
#define MAXCALLNUM 30

using namespace llvm;
using namespace std;

extern stringsetMap CallMap;
extern std::map<std::string, int> myCallerCountMap;
extern std::map<std::string, int> myCalleeCountMap;
extern stringsetMap sys_calleemap;
extern strset sys_calleeset;
extern stringsetMap sysLIdMap; 
extern stringsetMap sysSIdMap;
extern std::string syscaller;
extern stringsetMap depmap;
extern strset sysfunc;
extern strset LIdset;
extern strset SIdset;
extern stringsetMap LIdMap; 
extern stringsetMap SIdMap;
extern int DvConditionBranches;
extern strset globalSIdSet;

void dumpCallMap();
void circle_callee(std::string caller, int layer);
std::vector<std::string> split(std::string str,std::string pattern);
void createdepmap();
void dumpdepmap();
void dumpbcfile();
void printTypeRecursive(Type *targetType, bool first, std::vector<std::string> &tyVec);

#endif
