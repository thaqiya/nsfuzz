/*
 * Call graph construction
 *
 * Copyright (C) 2012 Xi Wang, Haogang Chen, Nickolai Zeldovich
 * Copyright (C) 2015 - 2016 Chengyu Song 
 * Copyright (C) 2016 Kangjie Lu
 *
 * For licensing details see LICENSE
 */


// add MLTA from CCS 2019 Kangjie Lu's paper, which is the best paper award winner

/*
 processInitializers: 
    Recursively handle scenarios where variable variables are initialized with function pointers
    If initialized to a structure, recursively process structure members to see if any members are function pointers
    The structure uses getOperand(i) to access the members
doModulePass
    doFunctionPass
 */

#include "CallGraph.h"
#include "Annotation.h"
#include "Common.h"
#include "DepAnalysis.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/IR/Dominators.h"
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/Pass.h>
#include <llvm/Support/Debug.h>

#define TYPE_BASED
#define MLTA_BASED
#define OS llvm::errs()
#define Diag llvm::errs()
// #define DEBUG
// #define DEBUG_MLTA

using namespace llvm;
using namespace std;

std::map<std::string, int> CallerCountMap;
std::map<std::string, int> CalleeCountMap;
DenseMap<size_t, FuncSet> typeFuncsMap;
unordered_map<size_t, set<size_t>> typeConfineMap;
unordered_map<size_t, set<size_t>> typeTransitMap;
set<size_t> typeEscapeSet;
std::map<llvm::Loop *, llvm::Function*> LoopMap;
FuncSet AnalyzedFunc;
strset LoopAnalyzedFunc;
VarMap Vmap;

extern strset LIdset;
extern strset SIdset;
extern strset gLIdset;
extern strset gSIdset;
extern std::map<std::string, IdInstMap> LInstMap;
extern std::map<std::string, IdInstMap> SInstMap;
extern string InputBackTrace;
extern bool dumpCG;

static strset glibc_struct = {"bool_t", "re_dfastate_t_0", "argp_option", "mallinfo", "r_search_path_elem", "hol_cluster", "int64_t", "strbuf", "gid_t", "re_token_t", "FILE_0", "statfs64", "FTSENT", "ip6_opt", "sockaddr", "libc_ifunc_impl", "fmemopen_cookie_struct", "pentry_state", "parser_sizes", "exit_function", "argp_state", "cmsghdr", "nlmsghdr", "netaddr", "prefixlist", "Elf64_Dyn_0", "scandir_cancel_struct", "extra_entry", "ext_match::patternlist", "THOUSANDS_SEP_T_0", "clockid_t", "sockaddr_iso", "malloc_par", "sigset_t", "vtimes", "printf_info", "pthread_attr_t_0", "sysdep_string", "bin_tree_t", "protoent", "Elf64_Dyn", "size_t", "locale_t", "codestrs_t_8", "derivation_step", "gr_response_header", "sockaddr_dl", "locale_data_t_0", "FTW", "cu_data", "wctype_t", "make_request::req", "regmatch_t", "glob_t_0", "archmapped", "td_thr_events", "key_netstres", "known_derivation", "sysdep_segment", "netlink_res", "spwd", "rpc_err", "auth_ops", "ct_data", "addrinfo", "mutex_t", "key_netstres_0", "cryptkeyarg_0", "mode_t", "Elf64_Vernaux", "u_long", "fork_handler_pool", "nscd_time_t", "locale_in_archive", "re_dfa_t_0", "gaih_addrtuple", "msghdr", "ether_addr", "lldiv_t", "group", "speed_t", "statvfs64", "unique_sym", "rpcproc_t", "va_list", "rmtcallargs", "yytype_uint8", "DIR", "lconv", "ieee754_double", "pthread_mutex_t", "gconv_module", "Elf64_Sym", "yytype_int16", "in_pktinfo", "int8_t", "link_map_machine", "rusage", "wordexp_t", "ifaddrs_storage", "sockaddr_ns", "database_pers_head", "UDItype", "codestrs_t_4", "f_owner_ex", "bracket_elem_t", "parser_data", "byte", "re_registers", "ui32", "gconvcache_header", "re_string_t", "pthread_key_data", "argp", "prof", "innetgroup_response_header", "xp_ops", "Elf64_Verdaux", "pthread_mutexattr_t", "pthread_t", "des_block_0", "RECSTREAM", "accepted_reply", "La_x86_64_regs", "greg_t", "region", "re_dfastate_t", "glob_in_dir::globnames", "bin_tree_t_0", "hol_help_state", "wint_t", "SVCXPRT_0", "cache_node", "fd_mask", "XDR", "utmpx", "hol", "malloc_state", "netlink_handle", "open_wmemstream::locked_FILE", "Elf_Symndx", "stat", "state_array_t", "cryptkeyarg", "cpu_features", "authdes_fullname", "ifaddrs", "sockaddr_in6", "FTS", "in_addr", "timeb", "sysinfo", "La_x86_64_zmm", "re_dfa_t", "hconf", "u_int", "unix_conn", "locked_map_ptr", "r_found_version", "pthread_key_struct", "Elf64_Xword", "cryptkeyarg2", "str_list", "ext_wmatch::patternlist", "tm", "sigvec", "nscd_ai_result", "rpc_createerr", "ssize_t", "getcredres", "initgr_response_header", "dtv_slotinfo_list", "pthread_rwlock_t", "ttyent", "qelem", "coll_seq_0", "nl_item", "node_t", "module_entry", "dl_phdr_info", "udp_cache", "pthread_unwind_buf", "hostent", "hack_digit_param", "wchar_t", "Elf32_Word", "FILE", "fd_set", "Elf64_Off", "posix_spawnattr_t", "utsname", "termios", "svcudp_data", "rpcvers_t", "r_file_id", "Dl_info", "ip6_rthdr0", "fork_handler", "dl_scope_free_list", "uparams", "yyalloc", "mo_file_header", "ptrdiff_t", "list_t", "mcontext_t", "gaih_servtuple", "obstack", "mp_size_t", "trace_arg", "rpc_thread_variables", "fpu_control_t", "bsdcred", "ifmap", "re_fail_stack_ent_t", "reply_body", "ttinfo", "catnamestr_t", "sockaddr_storage", "malloc_chunk", "sizetype", "epoll_data_t", "ifconf", "re_sub_match_top_t", "cmessage", "ref_t", "segment_pair", "Elf64_auxv_t", "authnone_private_s", "statvfs", "fnmatch_struct", "posix_spawn_file_actions_t", "locarhead", "rmtcallres", "sockaddr_ax25", "ip6_rthdr", "utmp", "intptr_t", "timex", "printf_spec_0", "stack_node", "netobj_0", "r_search_path_struct", "rtld_global", "sockaddr_eon", "pid_t", "hp_timing_t", "option", "request_header", "fmemopen_cookie_t", "hsearch_data", "random_data", "audata", "ENTRY", "helper_file", "service_user_0", "re_backref_cache_entry", "uint16_t", "cleanup_arg", "heap_info", "pollfd", "era_entry", "authdes_verf", "call_body", "reg_syntax_t", "ldiv_t", "kernel_dirent", "enum_t", "mbstate_t", "nlink_t", "msgstr_t", "atomic64_t", "u_char", "rec_strm", "fstab_state", "epoll_event", "write_call_graph::arc", "in_addr_t", "range", "keystatus_0", "u_short", "priority_protection_data", "sockaddr_at", "regoff_t", "libname_list", "key_netstarg", "parser", "char16_t", "hashentry", "binding", "sa_family_t", "abort_msg_s", "auth_errtab", "reloc_result", "ai_response_header", "rlimit", "tcbhead_t", "getcredres_0", "argp_fmtstream", "LONG_DOUBLE_16", "div_t", "La_x86_64_retval", "locale_data_t", "service_user", "gmon_cg_arc_record", "re_fail_stack_t", "scopeentry", "catalog_obj", "do_dlsym_args", "link_map_public", "Elf64_Word", "pthread_once_t", "write_hist::real_gmon_hist_hdr", "loaded_l10nfile", "sgttyb", "rpcprog_t", "regex_t", "leap", "sigaction", "int16_t", "dtor_list", "statfs", "mp_power", "utfuncs", "opaque_auth", "Elf64_Section", "rpc_timeval", "toktab", "printf_modifier_record", "rtld_global_ro", "bitset_word_t", "aliasent", "converted_domain", "sock_extended_err", "quad_t", "fpos_t", "path_elem", "loaded_domain", "re_state_table_entry", "timeval", "bin_tree_storage_t_0", "caddr_t", "La_x86_64_vector", "printf_spec", "cmd", "mmsghdr", "uparam_name", "sort_result", "extra_entry_module", "Elf32_Section", "Elf64_Addr", "xid_command", "hdr", "ucred", "intel_02_cache_info", "rpc_errtab", "La_x86_64_xmm", "ustat", "ntptimeval", "passwd", "nscd_ssize_t", "int32_t", "tms", "rlimit64", "La_x86_64_ymm", "pthread_key_t", "known_object", "tcp_conn", "transmem_block_t", "timespec", "td_eventbuf_t", "cached_data", "gmonparam", "namehashent", "name_database_entry_0", "rtattr", "sockaddr_x25", "link_map", "prefixentry", "Elf64_Verneed", "pmaplist", "fmemopen_cookie_struct_0", "u_int32_t", "speed_struct", "ftw_data", "pthread_condattr_t", "sigstack", "time_t", "sysdep_string_desc", "msort_param", "callrpc_private_s", "dl_tls_index", "tzhead", "argp_child", "uint8_t", "tls_index", "link_map_reldeps", "des_block", "long_int", "Elf64_Half", "parse_args", "rejected_reply", "call_dl_lookup_args", "key_netstarg_0", "locrecent", "Elf32_Sym", "traced_file", "sigaltstack", "etherent", "servent", "sockaddr_nl", "entry", "XDR_0", "mapped_database", "xdr_ops", "ino64_t", "useconds_t", "sigcontext", "service_library_0", "cryptkeyres", "ifinfomsg", "stack_t", "sockaddr_ipx", "re_string_t_0", "Elf64_Ehdr", "catalog_info", "rlim_t", "pthread", "netent", "CLIENT", "known_function", "ieee754_float", "int_fast32_t", "parser_convert_state", "unique_sym_table", "locale_data_value", "Elf64_Sym_0", "tzstring_l", "alias_map", "lc_time_data", "unixcred", "name_database", "cryptkeyarg2_0", "dir_data", "in6addrinfo", "codestrs_t_11", "uint32_t", "gconv_alias", "scratch_buffer", "re_node_set", "Elf64_Phdr", "random_poly_info", "pthread_cond_2_0_t", "nls_uint32", "tostruct", "hol_entry", "pthread_cond_t", "string_desc", "dirent64", "prof_info", "Elf64_Verdef", "char_buffer", "nlmsgerr", "cc_t", "expression", "ip_msfilter", "ucontext_t", "off64_t", "gaih_typeproto", "yytype_int8", "pw_response_header", "td_thr_events_t", "build_trtable::dests_alloc", "sched_param", "sigval", "Elf64_Rela", "known_translation_t", "re_pattern_buffer", "netgroup_response_header", "stat64", "exit_status", "netobj", "link_namespaces", "key_call_private", "sigval_t", "char_buffer_0", "sockaddr_inarp", "error_t", "audit_ifaces", "cache_entry", "if_nameindex", "robust_list_head", "fnwmatch_struct", "in6_addr", "re_charset_t", "gaih_service", "tcflag_t", "iovec", "pmap", "proglst_", "do_dlopen_args", "Elf64_Versym", "cpuid_registers", "gconv_fcts", "dtv", "r_scope_elem", "scopelist", "ip6_ext", "codestrs_t_7", "ifaddrmsg", "ieee854_long_double", "key_t", "exit_function_list", "siginfo_t", "socklen_t", "name_database_entry", "rpc_msg", "eventfd_t", "ptrs_to_free", "sighandler_t", "off_t", "list_head", "AUTH_0", "rpcent", "flock", "re_sub_match_last_t", "itimerval", "builtin_map", "codestrs_t_5", "timezone", "kernel_sigaction", "Elf32_Addr", "hash_entry", "clntraw_private_s", "svcraw_private_s", "tz_rule", "SVCXPRT", "dtv_slotinfo", "intmax_t", "rlim64_t", "ino_t", "AUTH", "cryptkeyres_0", "codestrs_t_29", "dirent", "name_database_0", "group_0", "cookie_io_functions_t", "transmem_list", "helper_file_0", "rtgenmsg", "u_int16_t", "auditstate", "codestrs_t_17", "u_quad_t", "mp_limb_t", "ax25_address", "unixcred_0", "name_list", "pthread_functions", "sockaddr_in", "YYSTYPE", "YYSTYPE_0", "authunix_parms", "svc_req", "svc_callout", "serv_response_header", "in_port_t", "dtv_t", "nfds_t", "ieee_long_double_shape_type", "cpu_set_t", "ifreq", "authdes_cred", "mntent", "printf_arg", "desparams", "coll_seq", "ucontext", "fmemopen_cookie_t_0", "ip6_hbh", "xdr_discrim", "Elf64_Sxword", "re_match_context_t", "sockaddr_ll_max", "clock_t", "uint64_t", "datahead", "group_filter", "bin_tree_storage_t", "severity_info", "sort_result_combo", "CLIENT_0", "uintptr_t", "id_t", "fstab", "sockaddr_un", "glob_t", "uint_fast32_t", "epoll_data", "ad_private", "re_sift_context_t", "clnt_ops", "dev_t", "atalk_addr", "r_debug", "sgrp", "uintmax_t", "dl_open_hook", "gidx_t", "ct_data_0", "hst_response_header", "write_gmon::real_gmon_hdr", "malloc_save_state", "u_int8_t", "Lmid_t", "wait", "tcp_rendezvous", "uid_t", "unix_rendezvous", "drand48_data", "service_library", "pthread_attr_t"};

static strset libc_input = { "read", "recv", "gets", "fgets", "receive", "Step"};
static strset SigHandlerSet;

std::string extract_str(std::string str, std::string pattern)
{
    std::string raw_str;
    std::string::size_type pos;
    std::vector<std::string> result;
    raw_str = str;
    // extend string length
    str += pattern;
    int size = str.size();

    if (str.find(pattern, 0) >= raw_str.size() || str.find("\n", 0) < raw_str.size())
    {
        return raw_str;
    }
    for (int i = 0; i < size; i++)
    {
        pos = str.find(pattern, i);
        if (pos < size && pos >= i)
        {
            std::string s = str.substr(i, pos - i);
            result.push_back(s);
            i = pos + pattern.size() - 1;
        }
    }
    if (result.size() <= 1)
        return raw_str;
    return result[result.size() - 1];
}

Function *CallGraphPass::getFuncDef(Function *F)
{
    FuncMap::iterator it = Ctx->Funcs.find(extract_str(getScopeName(F), ".llvm."));
    if (it != Ctx->Funcs.end())
        return it->second;
    else
        return F;
}

bool CallGraphPass::isCompositeType(Type *Ty)
{
    if (Ty->isStructTy() || Ty->isArrayTy() || Ty->isVectorTy())
        return true;
    else
        return false;
}

// Get the composite type of the lower layer. Layers are split by
// memory loads
Value *CallGraphPass:: nextLayerBaseType(Value *V, Type * &BTy, 
		int &Idx, const DataLayout *DL) {

#ifdef DEBUG
    errs() << " get nextLayerBaseType from: " << *V << "\n";
#endif
	// Two ways to get the next layer type: GetElementPtrInst and
	// LoadInst
	// Case 1: GetElementPtrInst
	if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V)) {
		Type *PTy = GEP->getPointerOperand()->getType();
		Type *Ty = PTy->getPointerElementType();
		if ((Ty->isStructTy() || Ty->isArrayTy() || Ty->isVectorTy()) 
				&& GEP->hasAllConstantIndices()) {
			BTy = Ty;
			User::op_iterator ie = GEP->idx_end();
			ConstantInt *ConstI = dyn_cast<ConstantInt>((--ie)->get());
			Idx = ConstI->getSExtValue();
			return GEP->getPointerOperand();
		}
		else
			return NULL;
	}
	// Case 2: LoadInst
	else if (LoadInst *LI = dyn_cast<LoadInst>(V)) {
		return nextLayerBaseType(LI->getOperand(0), BTy, Idx, DL);
	}
	// Other instructions such as CastInst
	// FIXME: may introduce false positives
#if 1
	else if (UnaryInstruction *UI = dyn_cast<UnaryInstruction>(V)) {
		return nextLayerBaseType(UI->getOperand(0), BTy, Idx, DL);
	}
#endif
	else
		return NULL;
}

bool CallGraphPass::isCompatibleType(Type *T1, Type *T2)
{
    if (T1->isPointerTy())
    {
        if (!T2->isPointerTy())
            return false;

        Type *ElT1 = T1->getPointerElementType();
        Type *ElT2 = T2->getPointerElementType();
        // assume "void *" and "char *" are equivalent to any pointer type
        if (ElT1->isIntegerTy(8) /*|| ElT2->isIntegerTy(8)*/)
            return true;

        return isCompatibleType(ElT1, ElT2);
    }
    else if (T1->isArrayTy())
    {
        if (!T2->isArrayTy())
            return false;

        Type *ElT1 = T1->getArrayElementType();
        Type *ElT2 = T2->getArrayElementType();
        return isCompatibleType(ElT1, ElT1);
    }
    else if (T1->isIntegerTy())
    {
        // assume pointer can be cased to the address space size
        if (T2->isPointerTy() && T1->getIntegerBitWidth() == T2->getPointerAddressSpace())
            return true;

        // assume all integer type are compatible
        if (T2->isIntegerTy())
            return true;
        else
            return false;
    }
    else if (T1->isStructTy())
    {
        StructType *ST1 = cast<StructType>(T1);
        StructType *ST2 = dyn_cast<StructType>(T2);
        if (!ST2)
            return false;

        // literal has to be equal
        if (ST1->isLiteral() != ST2->isLiteral())
            return false;

        // literal, compare content
        if (ST1->isLiteral())
        {
            unsigned numEl1 = ST1->getNumElements();
            if (numEl1 != ST2->getNumElements())
                return false;

            for (unsigned i = 0; i < numEl1; ++i)
            {
                if (!isCompatibleType(ST1->getElementType(i), ST2->getElementType(i)))
                    return false;
            }
            return true;
        }

        // not literal, use name?
        return ST1->getStructName().equals(ST2->getStructName());
    }
    else if (T1->isFunctionTy())
    {
        FunctionType *FT1 = cast<FunctionType>(T1);
        FunctionType *FT2 = dyn_cast<FunctionType>(T2);
        if (!FT2)
            return false;

        if (!isCompatibleType(FT1->getReturnType(), FT2->getReturnType()))
            return false;

        // assume varg is always compatible with varg?
        if (FT1->isVarArg())
        {
            if (FT2->isVarArg())
                return true;
            else
                return false;
        }

        // compare args, again ...
        unsigned numParam1 = FT1->getNumParams();
        if (numParam1 != FT2->getNumParams())
            return false;

        for (unsigned i = 0; i < numParam1; ++i)
        {
            if (!isCompatibleType(FT1->getParamType(i), FT2->getParamType(i)))
                return false;
        }
        return true;
    }
    else
    {
        // errs() << "Unhandled Types:" << *T1 << " :: " << *T2 << "\n";
        return T1->getTypeID() == T2->getTypeID();
    }
}

// find callees for indirect call based on type_based approach
bool CallGraphPass::findCalleesByType(CallInst *CI, FuncSet &FS)
{
    CallSite CS(CI);
    // errs() << "Indirect Call: " << *CI << "\n";
    for (Function *F : Ctx->AddressTakenFuncs)
    {

        // just compare known args
        if (F->getFunctionType()->isVarArg())
        {
            errs() << "VarArg: " << F->getName() << "\n";
            //report_fatal_error("VarArg address taken function\n");
        }
        else if (F->arg_size() != CS.arg_size())
        {
            // errs() << "ArgNum mismatch: " << F->getName() << "\n";
            continue;
        }
        // Check whether the return value type is consistent, 
        // that is, the return value of addresstaken function F and the return value of CallSite
        else if (!isCompatibleType(F->getReturnType(), CI->getType()))
        {
            continue;
        }
        if (F->isIntrinsic())
        {
            // errs() << "Intrinsic: " << F->getName() << "\n";
            continue;
        }

        // type matching on args
        // match arguments one by one
        bool Matched = true;
        CallSite::arg_iterator AI = CS.arg_begin();
        for (Function::arg_iterator FI = F->arg_begin(), FE = F->arg_end(); FI != FE; ++FI, ++AI)
        {
            // check type mis-match
            Type *FormalTy = FI->getType();
            Type *ActualTy = (*AI)->getType();

            if (isCompatibleType(FormalTy, ActualTy))
                continue;
            else
            {
                Matched = false;
                break;
            }
        }

        if (Matched)
        {
            FS.insert(F);
        }
    }

    return false;
}

bool CallGraphPass::findCalleesByMLTASingleLayer(CallInst *CI, FuncSet &FS) {

    // Initial set: first-layer results
    FuncSet FS1 = Ctx->sigFuncsMap[callHash(CI)];
    if (FS1.size() == 0) {
        // No need to go through MLTA if the first layer is empty
#ifdef DEBUG_MLTA
        errs() << "Call Inst: " << *CI << "\n";
        errs() << "no FuncSet found for callhash: " << callHash(CI) << "\n";
#endif
        return false;
    }

    FuncSet FS2, FST;

    Type *LayerTy = NULL;
    int FieldIdx = -1;
    Value *CV = CI->getCalledValue();

#ifdef DEBUG_MLTA
    errs() << "---------------------start MLTA-------------------------\n";
    errs() << "Call Inst: " << *CI << "\n";
    errs() << "Call Inst belongs to Function: " << CI->getFunction()->getName() << "\n";
    errs() << "Call Inst belogns to Module: " << CI->getModule()->getName() << "\n";
    errs() << "Called Value: " << *CV << "\n";
#endif // DEBUG
    // Get the second-layer type
    CV = nextLayerBaseType(CV, LayerTy, FieldIdx, DL);
    int LayerNo = 1;

    if (CV) {
        // Step 1: ensure the type hasn't escaped
        if ((typeEscapeSet.find(typeHash(LayerTy)) != typeEscapeSet.end()) || 
                (typeEscapeSet.find(typeIdxHash(LayerTy, FieldIdx)) !=
                 typeEscapeSet.end())) {
            errs() << "Type Escaped" << "\n";
        } else {
        // Step 2: get the funcset and merge
            ++LayerNo;
#ifdef DEBUG_MLTA
            // errs() << "Current Value" << *CV << "\n";
            errs() << "-------------------------------\nLayerNo: " << LayerNo << "\n";
            errs() << "Layer Type: " << *LayerTy << ", offset: " << FieldIdx << "\n";
            errs() << "typeIdxHash: " << typeIdxHash(LayerTy, FieldIdx) << "\n";
            errs() << "-------------------------------\n";
#endif // DEBUG
            FS2 = typeFuncsMap[typeIdxHash(LayerTy, FieldIdx)];
            FST.clear();
            funcSetIntersection(FS1, FS2, FST);
#ifdef DEBUG_MLTA
            errs() << "Last level FS1 size: " << FS1.size() << "\n";
            for (auto F : FS1){
                // errs() << F << "\n";
                errs() << F->getName() << "; ";
                errs() << "\n";
            }
            errs() << "Current level FS2 size: " << FS2.size() << "\n";
            for (auto F : FS2){
                // errs() << F << "\n";
                errs() << F->getName() << "; ";
                errs() << "\n";
            }
            errs() << "Intersection FST size: " << FST.size() << "\n";
#endif // DEBUG

        // Step 3: get transitted funcsets and merge
        // NOTE: this nested loop can be slow
#if 1
            unsigned TH = typeHash(LayerTy);
            list<unsigned> LT;
            LT.push_back(TH);
            while (!LT.empty()) {
                unsigned CT = LT.front();
                LT.pop_front();

                for (auto H : typeTransitMap[CT]) {
                    FS2 = typeFuncsMap[hashIdxHash(H, FieldIdx)];
                    FST.clear();
                    funcSetIntersection(FS1, FS2, FST);
                    FS1 = FST;
                }
            }
#endif
        }
        FS1 = FST;
    }

    FS = FS1;
#ifdef DEBUG_MLTA
    errs() << "Final FS size: " << FS.size() << "\n";
    for (auto F : FS)
    {
        // errs() << F << "\n";
        errs() << F->getName() << "; ";
        errs() << "\n";
    }
    errs() << "---------------------end MLTA-------------------------\n";
#endif // DEBUG
    return true;
}


// find callees for indirect call based on MLTA approach
bool CallGraphPass::findCalleesByMLTA(CallInst *CI, FuncSet &FS) {

	// Initial set: first-layer results
	FuncSet FS1 = Ctx->sigFuncsMap[callHash(CI)];
	if (FS1.size() == 0) {
		// No need to go through MLTA if the first layer is empty
		return false;
	}

	FuncSet FS2, FST;

	Type *LayerTy = NULL;
	int FieldIdx = -1;
	Value *CV = CI->getCalledValue();

	// Get the second-layer type
	CV = nextLayerBaseType(CV, LayerTy, FieldIdx, DL);

	int LayerNo = 1;
	while (CV) {
		// Step 1: ensure the type hasn't escaped
#if 1
		if ((typeEscapeSet.find(typeHash(LayerTy)) != typeEscapeSet.end()) || 
				(typeEscapeSet.find(typeIdxHash(LayerTy, FieldIdx)) !=
				 typeEscapeSet.end())) {

			break;
		}
#endif

		// Step 2: get the funcset and merge
		++LayerNo;
        // errs() << "LayerNo: " << LayerNo << "\n";
		FS2 = typeFuncsMap[typeIdxHash(LayerTy, FieldIdx)];
		FST.clear();
		//FS2非空
        if (!FS2.empty()){
            funcSetIntersection(FS1, FS2, FST);
#ifdef DEBUG
            errs() << "Last level FS1 size: " << FS1.size() << "\n";
            for (auto F : FS1){
                errs() << F << "\n";
                errs() << F->getName() << "; ";
                errs() << "\n";
            }
            errs() << "Current level FS2 size: " << FS2.size() << "\n";
            for (auto F : FS2){
                errs() << F << "\n";
                errs() << F->getName() << "; ";
                errs() << "\n";
            }
            errs() << "Intersection FST size: " << FST.size() << "\n";
#endif // DEBUG
        }
        else {
            //FS2为空，没有候选Callee，为了避免漏报，使用上一轮的匹配结果作为输出。
#ifdef DEBUG
            errs() << "Current level FS2 empty!\n";
#endif // DEBUG
            break;
        }


		// Step 3: get transitted funcsets and merge
		// NOTE: this nested loop can be slow
#if 1
		unsigned TH = typeHash(LayerTy);
		list<unsigned> LT;
		LT.push_back(TH);
		while (!LT.empty()) {
			unsigned CT = LT.front();
			LT.pop_front();

			for (auto H : typeTransitMap[CT]) {
				FS2 = typeFuncsMap[hashIdxHash(H, FieldIdx)];
				FST.clear();
				funcSetIntersection(FS1, FS2, FST);
				FS1 = FST;
			}
		}
#endif

		// Step 4: go to a lower layer
		CV = nextLayerBaseType(CV, LayerTy, FieldIdx, DL);
		FS1 = FST;
	}

	FS = FS1;

	return true;
}

void CallGraphPass::funcSetIntersection(FuncSet &FS1, FuncSet &FS2,
                                        FuncSet &FS)
{
    FS.clear();
    for (auto F : FS1) {
      for (auto F2 : FS2) {
        if (F->getName() == F2->getName())
          FS.insert(F);
      }
    }
}

bool CallGraphPass::mergeFuncSet(FuncSet &S, const std::string &Id, bool InsertEmpty)
{
    FuncPtrMap::iterator i = Ctx->FuncPtrs.find(Id);
    if (i != Ctx->FuncPtrs.end())
        return mergeFuncSet(S, i->second);
    else if (InsertEmpty)
        Ctx->FuncPtrs.insert(std::make_pair(Id, FuncSet()));
    return false;
}

bool CallGraphPass::mergeFuncSet(std::string &Id, const FuncSet &S, bool InsertEmpty)
{
    FuncPtrMap::iterator i = Ctx->FuncPtrs.find(Id);
    if (i != Ctx->FuncPtrs.end())
        return mergeFuncSet(i->second, S);
    else if (!S.empty())
        return mergeFuncSet(Ctx->FuncPtrs[Id], S);
    else if (InsertEmpty)
        Ctx->FuncPtrs.insert(std::make_pair(Id, FuncSet()));
    return false;
}

bool CallGraphPass::mergeFuncSet(FuncSet &Dst, const FuncSet &Src)
{
    bool Changed = false;
    for (FuncSet::const_iterator i = Src.begin(), e = Src.end(); i != e; ++i)
    {
        assert(*i);
        Changed |= Dst.insert(*i).second;
    }
    return Changed;
}

bool CallGraphPass::findFunctions(Value *V, FuncSet &S)
{
    SmallPtrSet<Value *, 4> Visited;
    return findFunctions(V, S, Visited);
}

bool CallGraphPass::findFunctions(Value *V, FuncSet &S,
                                  SmallPtrSet<Value *, 4> Visited)
{
    if (!Visited.insert(V).second)
        return false;

    // real function, S = S + {F}
    if (Function *F = dyn_cast<Function>(V))
    {
        // prefer the real definition to declarations
        F = getFuncDef(F);
        return S.insert(F).second;
    }

    // bitcast, ignore the cast
    if (CastInst *B = dyn_cast<CastInst>(V))
        return findFunctions(B->getOperand(0), S, Visited);

    // const bitcast, ignore the cast
    if (ConstantExpr *C = dyn_cast<ConstantExpr>(V))
    {
        if (C->isCast())
        {
            return findFunctions(C->getOperand(0), S, Visited);
        }
        // FIXME GEP
    }

    if (GetElementPtrInst *G = dyn_cast<GetElementPtrInst>(V))
    {
        return false;
    }
    else if (isa<ExtractValueInst>(V))
    {
        return false;
    }

    if (isa<AllocaInst>(V))
    {
        return false;
    }

    if (BinaryOperator *BO = dyn_cast<BinaryOperator>(V))
    {
        Value *op0 = BO->getOperand(0);
        Value *op1 = BO->getOperand(1);
        if (!isa<Constant>(op0) && isa<Constant>(op1))
            return findFunctions(op0, S, Visited);
        else if (isa<Constant>(op0) && !isa<Constant>(op1))
            return findFunctions(op1, S, Visited);
        else
            return false;
    }

    // PHI node, recursively collect all incoming values
    if (PHINode *P = dyn_cast<PHINode>(V))
    {
        bool Changed = false;
        for (unsigned i = 0; i != P->getNumIncomingValues(); ++i)
            Changed |= findFunctions(P->getIncomingValue(i), S, Visited);
        return Changed;
    }

    // select, recursively collect both paths
    if (SelectInst *SI = dyn_cast<SelectInst>(V))
    {
        bool Changed = false;
        Changed |= findFunctions(SI->getTrueValue(), S, Visited);
        Changed |= findFunctions(SI->getFalseValue(), S, Visited);
        return Changed;
    }

    // arguement, S = S + FuncPtrs[arg.ID]
    if (Argument *A = dyn_cast<Argument>(V))
    {
        bool InsertEmpty = isFunctionPointer(A->getType());
        return mergeFuncSet(S, getArgId(A), InsertEmpty);
    }

    // return value, S = S + FuncPtrs[ret.ID]
    if (CallInst *CI = dyn_cast<CallInst>(V))
    {
        // update callsite info first
        FuncSet &FS = Ctx->Callees[CI];
        //FS.setCallerInfo(CI, &Ctx->Callers);
        findFunctions(CI->getCalledValue(), FS);
        bool Changed = false;
        for (Function *CF : FS)
        {
            bool InsertEmpty = isFunctionPointer(CI->getType());
            Changed |= mergeFuncSet(S, getRetId(CF), InsertEmpty);
        }
        return Changed;
    }

    // loads, S = S + FuncPtrs[struct.ID]
    if (LoadInst *L = dyn_cast<LoadInst>(V))
    {
        std::string Id = getLoadId(L);
        if (!Id.empty())
        {
            bool InsertEmpty = isFunctionPointer(L->getType());
            return mergeFuncSet(S, Id, InsertEmpty);
        }
        else
        {
            Function *f = L->getParent()->getParent();
            // errs() << "Empty LoadID: " << extract_str(F->getName(), ".llvm.") << "::" << *L << "\n";
            return false;
        }
    }

    // ignore other constant (usually null), inline asm and inttoptr
    if (isa<Constant>(V) || isa<InlineAsm>(V) || isa<IntToPtrInst>(V))
        return false;

    //V->dump();
    //report_fatal_error("findFunctions: unhandled value type\n");
    // errs() << "findFunctions: unhandled value type: " << *V << "\n";
    return false;
}

bool CallGraphPass::findCallees(CallInst *CI, FuncSet &FS)
{
#ifdef DEBUG
    Diag << "findCallees for " << *CI << "\n";
#endif
    Function *CF = CI->getCalledFunction();

    if (CF)
    {
        // prefer the real definition to declarations
        CF = getFuncDef(CF);
        // errs() << "direct call: " << F->getName() << "\n";
        return FS.insert(CF).second;
    }

    // save called values for point-to analysis
    Ctx->IndirectCallInsts.push_back(CI);

#ifdef MLTA_BASED
    // return findCalleesByMLTA(CI, FS);
    return findCalleesByMLTASingleLayer(CI, FS);
#endif

#ifdef TYPE_BASED
    // use type matching to concervatively find
    // possible targets of indirect call
    return findCalleesByType(CI, FS);
#else
    // use assignments based approach to find possible targets
    return findFunctions(CI->getCalledValue(), FS);
#endif
}

bool CallGraphPass::runOnFunction(Function *F)
{
    bool Changed = false;

    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i)
    {
        Instruction *I = &*i;
        // map callsite to possible callees
        if (CallInst *CI = dyn_cast<CallInst>(I))
        {
            // ignore inline asm or intrinsic calls
            if (CI->isInlineAsm() || (CI->getCalledFunction() && CI->getCalledFunction()->isIntrinsic()))
                continue;

            // collect signal handler
            Function *Func = CI->getCalledFunction();
            if (Func && (Func->getName() == "signal")) {
                Value *V = CI->getArgOperand(1);
                string handler = V->getName();
                if (!handler.empty()) {
                    errs() << "handler name: " << handler << "\n";
                    SigHandlerSet.insert(handler);
                }
            }
            // might be an indirect call, find all possible callees
            //Ctx->Callees[CI] 代表CallInst调用点的所有候选callee集合
            FuncSet &FS = Ctx->Callees[CI];
            if (!findCallees(CI, FS))
                continue;
#if (!defined TYPE_BASED) && (!defined MLTA_BASED)
// #ifndef TYPE_BASED
            // looking for function pointer arguments
            for (unsigned no = 0, ne = CI->getNumArgOperands(); no != ne; ++no)
            {
                Value *V = CI->getArgOperand(no);
                if (!isFunctionPointerOrVoid(V->getType()))
                    continue;

                // find all possible assignments to the argument
                FuncSet VS;
                if (!findFunctions(V, VS))
                    continue;

                // update argument FP-set for possible callees
                for (Function *CF : FS)
                {
                    if (!CF)
                    {
                        WARNING("NULL Function " << *CI << "\n");
                        assert(0);
                    }
                    std::string Id = getArgId(CF, no);
                    Changed |= mergeFuncSet(Ctx->FuncPtrs[Id], VS);
                }
            }
#endif
        }
// #ifndef TYPE_BASED
#if (!defined TYPE_BASED) && (!defined MLTA_BASED)
        if (StoreInst *SI = dyn_cast<StoreInst>(I))
        {
            // stores to function pointers
            Value *V = SI->getValueOperand();
            if (isFunctionPointerOrVoid(V->getType()))
            {
                std::string Id = getStoreId(SI);
                if (!Id.empty())
                {
                    FuncSet FS;
                    findFunctions(V, FS);
                    Changed |= mergeFuncSet(Id, FS, isFunctionPointer(V->getType()));
                }
            }
        }
        else if (ReturnInst *RI = dyn_cast<ReturnInst>(I))
        {
            // function returns
            if (isFunctionPointerOrVoid(F->getReturnType()))
            {
                Value *V = RI->getReturnValue();
                std::string Id = getRetId(F);
                FuncSet FS;
                findFunctions(V, FS);
                Changed |= mergeFuncSet(Id, FS, isFunctionPointer(V->getType()));
            }
        }
#endif
    }

    return Changed;
}

bool CallGraphPass::typeConfineInStore(StoreInst *SI)
{

    Value *PO = SI->getPointerOperand();
    Value *VO = SI->getValueOperand();

    // Case 1: The value operand is a function
    if (Function *F = dyn_cast<Function>(VO))
    {
        Type *STy;
        int Idx;
        if (nextLayerBaseType(PO, STy, Idx, DL))
        {
            typeFuncsMap[typeIdxHash(STy, Idx)].insert(F);
            return true;
        }
        else
        {
            // TODO: OK, for now, let's only consider composite type;
            // skip for other cases
            return false;
        }
    }

    // Cast 2: value-based store
    // A composite-type object is stored
    Type *EPTy = dyn_cast<PointerType>(PO->getType())->getElementType();
    Type *VTy = VO->getType();
    if (isCompositeType(VTy))
    {
        if (isCompositeType(EPTy))
        {
            typeConfineMap[typeHash(EPTy)].insert(typeHash(VTy));
            return true;
        }
        else
        {
            escapeType(EPTy);
            return false;
        }
    }

    // Case 3: reference (i.e., pointer)-based store
    if (isa<ConstantPointerNull>(VO))
        return false;
    // FIXME: Get the correct types
    PointerType *PVTy = dyn_cast<PointerType>(VO->getType());
    if (!PVTy)
        return false;

    Type *EVTy = PVTy->getElementType();

    // Store something to a field of a composite-type object
    Type *STy;
    int Idx;
    if (nextLayerBaseType(PO, STy, Idx, DL))
    {
        // The value operand is a pointer to a composite-type object
        if (isCompositeType(EVTy))
        {
            typeConfineMap[typeIdxHash(STy,Idx)].insert(typeHash(EVTy));
            return true;
        }
        else
        {
            // TODO: The type is escaping?
            // Example: mm/mempool.c +188: pool->free = free_fn;
            // free_fn is a function pointer from an function
            // argument
            escapeType(STy, Idx);
            return false;
        }
    }

    return false;
}

bool CallGraphPass::typeConfineInCast(CastInst *CastI)
{

    // If a function address is ever cast to another type and stored
    // to a composite type, the escaping analysis will capture the
    // composite type and discard it

    Value *ToV = CastI, *FromV = CastI->getOperand(0);
    Type *ToTy = ToV->getType(), *FromTy = FromV->getType();
    if (isCompositeType(FromTy))
    {
        transitType(ToTy, FromTy);
        return true;
    }

    if (!FromTy->isPointerTy() || !ToTy->isPointerTy())
        return false;
    Type *EToTy = dyn_cast<PointerType>(ToTy)->getElementType();
    Type *EFromTy = dyn_cast<PointerType>(FromTy)->getElementType();
    if (isCompositeType(EToTy) && isCompositeType(EFromTy))
    {
        transitType(EToTy, EFromTy);
        return true;
    }

    return false;
}

void CallGraphPass::escapeType(Type *Ty, int Idx)
{
    if (Idx == -1)
        typeEscapeSet.insert(typeHash(Ty));
    else
        typeEscapeSet.insert(typeIdxHash(Ty, Idx));
}

void CallGraphPass::transitType(Type *ToTy, Type *FromTy,
                                int ToIdx, int FromIdx)
{
    if (ToIdx != -1 && FromIdx != -1)
        typeTransitMap[typeIdxHash(ToTy,ToIdx)].insert(typeIdxHash(FromTy, FromIdx));
    else
        typeTransitMap[typeHash(ToTy)].insert(typeHash(FromTy));
}

// collect function pointer assignments in global initializers
void CallGraphPass::processInitializers(Module *M, Constant *C, GlobalValue *V, std::string Id)
{
    // structs
    // ConstantStruct globale variable type declare
    // sub type in struct + variable name
#ifdef DEBUG
    if (M != nullptr)
        errs() << "CallGraphPass::processInitializers: Module " << M->getName() << "\n";
    if (C != nullptr)
        errs() << "Constant: " << *C << "\n";
    if (V != nullptr)
        errs() << "GlobalValue: " << *V << "\n";
    errs() << "Id: " << Id << "\n";
#endif
    if (ConstantStruct *CS = dyn_cast<ConstantStruct>(C))
    {
        // StructType type info of global variables
        // that is, type info in ConstantStruct
        StructType *STy = CS->getType();
    
        if ((!STy->hasName() || STy->isLiteral()) && Id.empty() && V != nullptr)
        {
            Id = getVarId(V);
#ifdef DEBUG
            errs() << "Id = getVarId(V): " << Id << "\n";
#endif
        }
        for (unsigned i = 0; i != STy->getNumElements(); ++i)
        {
            Type *ETy = STy->getElementType(i);
#ifdef DEBUG
            errs() << "Type: " << *ETy << "\n";
#endif
            if (ETy->isStructTy())
            {
                std::string new_id;
                if (Id.empty() && !STy->isLiteral())
                    new_id = STy->getStructName().str() + "," + std::to_string(i);
                else
                    new_id = Id + "," + std::to_string(i);
                processInitializers(M, CS->getOperand(i), NULL, new_id);
            }
            else if (ETy->isArrayTy())
            {
                // nested array of struct
                processInitializers(M, CS->getOperand(i), NULL, "");
            }
            else if (isFunctionPointer(ETy))
            {
                // found function pointers in struct fields
                if (Function *F = dyn_cast<Function>(CS->getOperand(i)))
                {
                    std::string new_id;
                    if (!STy->isLiteral())
                    {
                        // STy is a struct definition
                        if (STy->getStructName().startswith("struct.anon.") ||
                            STy->getStructName().startswith("union.anon"))
                        {
                            if (Id.empty())
                                new_id = getStructId(STy, M, i);
                        }
                        else
                        {
                            new_id = getStructId(STy, M, i);
                        }
                    }
                    if (!new_id.empty() || !Id.empty()) {
                        if (new_id.empty()) {
                          new_id = Id + "," + std::to_string(i);
                        }
                        // new_id is (struct type + offset) to present function
                        // pointer
                        Ctx->FuncPtrs[new_id].insert(getFuncDef(F));
                    }
                }
            }
        }
    }
    else if (ConstantArray *CA = dyn_cast<ConstantArray>(C))
    {
        // array, conservatively collects all possible pointers
        for (unsigned i = 0; i != CA->getNumOperands(); ++i)
            processInitializers(M, CA->getOperand(i), V, Id);
    }
    else if (Function *F = dyn_cast<Function>(C))
    {
        // global function pointer variables
        if (V)
        {
            std::string Id = getVarId(V);
#ifdef DEBUG
            errs() << "new id: " << Id << "\n";
#endif
            Ctx->FuncPtrs[Id].insert(getFuncDef(F));
        }
    }
}

bool CallGraphPass::typeConfineInInitializer(User *Ini)
{

    list<User *> LU;
    LU.push_back(Ini);

    while (!LU.empty())
    {
        User *U = LU.front();
        LU.pop_front();
#ifdef DEBUG
        errs() << "\nConfine ConstantStruct: " << *U << "\n";
#endif
        int idx = 0;
        for (auto oi = U->op_begin(), oe = U->op_end();
             oi != oe; ++oi)
        {
            Value *O = *oi;
            Type *OTy = O->getType();
            // Case 1: function address is assigned to a type
            if (Function *F = dyn_cast<Function>(O))
            {
                // ITy为嵌套F的结构体
                Type *ITy = U->getType();
                // TODO: use offset?
                unsigned ONo = oi->getOperandNo();
#ifdef DEBUG
                errs() << "Function Type: " << *(F->getType()) << "\n";
                errs() << "Hash id: Type: " << *ITy << ", offset: " << ONo << "\n";
                errs() << "typeIdxHash: " << typeIdxHash(ITy, ONo) << "\n";
#endif // DEBUG
                typeFuncsMap[typeIdxHash(ITy, ONo)].insert(F);
            }
            // Case 2: a composite-type object (value) is assigned to a
            // field of another composite-type object
            else if (isCompositeType(OTy))
            {
                // confine composite types
                Type *ITy = U->getType();
                unsigned ONo = oi->getOperandNo();
#ifdef DEBUG
                errs() << "Type: " << *OTy << " offset: " << ONo << "\n";
                errs() << "typeIdxHash: " << typeIdxHash(ITy, ONo) << "\n";
#endif // DEBUG
                typeConfineMap[typeIdxHash(ITy, ONo)].insert(typeHash(OTy));

                // recognize nested composite types
                User *OU = dyn_cast<User>(O);
                LU.push_back(OU);
            }
            // Case 3: a reference (i.e., pointer) of a composite-type
            // object is assigned to a field of another composite-type
            // object
            else if (PointerType *POTy = dyn_cast<PointerType>(OTy))
            {
                if (isa<ConstantPointerNull>(O))
                    continue;
                // if the pointer points a composite type, skip it as
                // there should be another initializer for it, which
                // will be captured

                // now consider if it is a bitcast from a function
                // address
                if (BitCastOperator *CO =
                        dyn_cast<BitCastOperator>(O))
                {
                    // TODO: ? to test if all address-taken functions
                    // are captured
                }
            }
        }
    }

    return true;
}

bool CallGraphPass::doInitialization(Module *M)
{
    DL = &(M->getDataLayout());
    // collect function pointer assignments in global initializers
    for (GlobalVariable &G : M->globals())
    {
        // hasInitializer - Definitions have initializers, declarations don't.
        if (G.hasInitializer())
        {
            #ifdef DEBUG
                        errs() << "GlobalVariable: " << G << "\n";
            #endif
            // getInitializer - Return the initializer for this global variable.
            // The main purpose is to collect the function pointer information in the global variable structure 
            // and establish the mapping through new_id
            // Ctx->FuncPtrs[Id].insert(getFuncDef(F));
            processInitializers(M, G.getInitializer(), &G, "");
#ifdef MLTA_BASED
            // when enable MLTA and initialize global variables
            // build map of typeConfineMap[hash(struct, idx)] = icall
            typeConfineInInitializer(G.getInitializer());
#endif
        }
    }

    for (Function &F : *M)
    {
#ifdef MLTA_BASED
        if (F.isDeclaration())
            continue;

        for (inst_iterator i = inst_begin(F), e = inst_end(F);
             i != e; ++i)
        {
            Instruction *I = &*i;
            // store instruction assigns value to function pointer
            if (StoreInst *SI = dyn_cast<StoreInst>(I))
                typeConfineInStore(SI);
            else if (CastInst *CastI = dyn_cast<CastInst>(I))
                typeConfineInCast(CastI);
        }

        // Collect global function definitions.
        if (F.hasExternalLinkage() && !F.empty())
        {
            // External linkage always ends up with the function name.
            StringRef FName = F.getName();
            // Special case: make the names of syscalls consistent.
            if (FName.startswith("SyS_"))
                FName = StringRef("sys_" + FName.str().substr(4));

            // Map functions to their names.
            Ctx->GlobalFuncs[FName] = &F;
        }

        // Keep a single copy for same functions (inline functions)
        size_t fh = funcHash(&F);
        if (Ctx->UnifiedFuncMap.find(fh) == Ctx->UnifiedFuncMap.end())
        {
            Ctx->UnifiedFuncMap[fh] = &F;
            Ctx->UnifiedFuncSet.insert(&F);

        }
#endif
        // collect address-taken functions
        // hasAddressTaken - returns true if there are any uses of this function other than direct calls or invokes to it, or blockaddress expressions.
        if (F.hasAddressTaken())
        {
            Ctx->AddressTakenFuncs.insert(&F);
            Ctx->sigFuncsMap[funcHash(&F, false)].insert(&F);
#ifdef DEBUG
            errs() << "sigFuncsMap[F] count After function: " << F.getName() << ", " << Ctx->sigFuncsMap[funcHash(&F, false)].size() << "\n";
            errs() << "funcHash(&F, false): " << funcHash(&F, false) << "\n";
#endif
        }
        else{
            //对没有addresstaken的函数也存储签名，通过MLTA来匹配。
            Ctx->sigFuncsMap[funcHash(&F, false)].insert(&F);
#ifdef DEBUG
            errs() << "Function has no address taken: " << F.getName() << "\n ";
            errs() << "funcHash(&F, false): " << funcHash(&F, false) << "\n";
#endif      

        }
        
    }

    return false;
}

bool CallGraphPass::doFinalization(Module *M)
{

    // update callee mapping
    for (Function &F : *M)
    {
        for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i)
        {
            // map callsite to possible callees
            if (CallInst *CI = dyn_cast<CallInst>(&*i))
            {
                FuncSet &FS = Ctx->Callees[CI];
                // calculate the caller info here
                for (Function *CF : FS)
                {
                    CallInstSet &CIS = Ctx->Callers[CF];
                    CIS.insert(CI);
                }
            }
        }
    }

    return false;
}

bool CallGraphPass::doModulePass(Module *M)
{
    bool Changed = true, ret = false;
    while (Changed)
    {
        Changed = false;
        for (Function &F : *M)
            Changed |= runOnFunction(&F);
        ret |= Changed;
    }
    return ret;
}

// debug
void CallGraphPass::dumpFuncPtrs()
{
    //raw_ostream &OS = outs();
    for (FuncPtrMap::iterator i = Ctx->FuncPtrs.begin(),
                              e = Ctx->FuncPtrs.end();
         i != e; ++i)
    {
        //if (i->second.empty())
        //    continue;
        OS << i->first << "\n";
        FuncSet &v = i->second;
        for (FuncSet::iterator j = v.begin(), ej = v.end();
             j != ej; ++j)
        {
            OS << "  " << ((*j)->hasInternalLinkage() ? "f" : "F")
               << " " << extract_str((*j)->getName(), ".llvm.") << "\n";
        }
    }
}

stringsetMap CallGraphPass::dumpCallees()
{
    stringsetMap CallMap;
    RES_REPORT("\n[dumpCallees]\n");
    //raw_ostream &OS = outs();
    std::string Caller;
    std::string Callee;
    //OS << "Num of Callees: " << Ctx->Callees.size() << "\n";
    for (CalleeMap::iterator i = Ctx->Callees.begin(), e = Ctx->Callees.end(); i != e; ++i)
    {
        CallInst *CI = i->first;
        FuncSet &v = i->second;
        // only dump indirect call?
        //if (CI->isInlineAsm() || CI->getCalledFunction() /*|| v.empty()*/)
        //   continue;
        // getCalledFunction() Return the function called, or null if this is an indirect function invocation
        if (v.empty() || CI->isInlineAsm() || (CI->getCalledFunction() && CI->getCalledFunction()->isIntrinsic()))
            continue;
        Function *CallerF = CI->getParent()->getParent();
        // #ifdef DEBUG
        //         errs() << "CI's Caller(CallerF): " << *CallerF << "\n";
        // #endif
        //RES_REPORT("\t");
        //v = Ctx->Callees[CI];
        if (CallerF && CallerF->hasName())
        {
            std::string Caller = extract_str(getScopeName(CallerF), ".llvm.");
            ///OS << "Caller:" << Caller << ": ";
            ///OS << "Callees: ";
            if (CallMap.count(Caller) == 0)
            {
                strset Calleeset;
                for (FuncSet::iterator j = v.begin(), ej = v.end(); j != ej; ++j)
                {
                    std::string Callee = extract_str((*j)->getName(), ".llvm.");
                    ;
                    if (Callee != Caller && Calleeset.count(Callee) == 0)
                    {
                        ///OS << Callee << "::";
#ifdef DEBUG
                        errs() << "Caller: " << Caller << " insert Callee: " << Callee << "\n";
#endif
                        if (CallerCountMap.count(Callee) == 0)
                            CallerCountMap[Callee] = 1;
                        else
                            CallerCountMap[Callee] += 1;
                        if (CalleeCountMap.count(Caller) == 0)
                            CalleeCountMap[Caller] = 1;
                        else
                            CalleeCountMap[Caller] += 1;
                        Calleeset.insert(Callee);
                    }
                }
                CallMap.insert({Caller, Calleeset});
            }
            else
            {
                for (FuncSet::iterator j = v.begin(), ej = v.end(); j != ej; ++j)
                {
                    std::string Callee = extract_str((*j)->getName(), ".llvm.");
                    if (Callee != Caller && CallMap[Caller].count(Callee) == 0)
                    {
                        ///OS << Callee << "::";
#ifdef DEBUG
                        errs() << "Caller: " << Caller << " insert Callee: " << Callee << "\n";
#endif
                        if (CallerCountMap.count(Callee) == 0)
                            CallerCountMap[Callee] = 1;
                        else
                            CallerCountMap[Callee] += 1;
                        if (CalleeCountMap.count(Caller) == 0)
                            CalleeCountMap[Caller] = 1;
                        else
                            CalleeCountMap[Caller] += 1;
                        CallMap[Caller].insert(Callee);
                    }
                }
            }

        }
        else
            RES_REPORT("(anonymous):");
    }
    return CallMap;
    RES_REPORT("\n[End of dumpCallees]\n");
}

std::map<std::string, int> CallGraphPass::dumpCallerCountMap()
{
    return CallerCountMap;
}

std::map<std::string, int> CallGraphPass::dumpCalleeCountMap()
{
    return CalleeCountMap;
}

void CallGraphPass::dumpCallers()
{
    RES_REPORT("\n[dumpCallers]\n");
    for (auto M : Ctx->Callers)
    {
        Function *F = M.first;
        CallInstSet &CIS = M.second;
        RES_REPORT("F : " << extract_str(getScopeName(F), ".llvm.") << "\n");
        //RES_REPORT("F : " << *F << "\n");

        for (CallInst *CI : CIS)
        {
            Function *CallerF = CI->getParent()->getParent();
            RES_REPORT("\t");
            if (CallerF && CallerF->hasName())
            {
                RES_REPORT("(" << extract_str(getScopeName(CallerF), ".llvm.") << ") ");
            }
            else
            {
                RES_REPORT("(anonymous) ");
            }

            RES_REPORT(*CI << "\n");
        }
    }
    RES_REPORT("\n[End of dumpCallers]\n");
}

void CallGraphPass::LoopCollect() {
    RES_REPORT("\n[LoopCollect]\n");
    set<llvm::Function *> FuncLoopToRemove;
    for (ModuleList::iterator i = Ctx->Modules.begin(), e = Ctx->Modules.end(); i != e; ++i) {
        for (Function &F : *i->first) {
            errs() << "get in func: " << F.getName() << "\n";
            if (F.isDeclaration()) {
                errs() << "func skip: " << F.getName() << "\n";
                continue;
            }

            // the target loop's outer func should have at most 1 potential loop
            bool has_loop = false;
            
            if (LoopAnalyzedFunc.count(F.getName()) == 0)
                LoopAnalyzedFunc.insert(F.getName());
            else {
                errs() << "duplicate func skip: " << F.getName() << "\n";
                continue;
            }

            llvm::DominatorTree DT1 = llvm::DominatorTree();
            DT1.recalculate(F);
            LoopInfo *loopInfo = new LoopInfo();
            loopInfo->releaseMemory();
            loopInfo->analyze(DT1);

            for (llvm::LoopInfo::iterator lit = loopInfo->begin(); lit != loopInfo->end(); lit++) {
                Loop *L = *lit;
                errs() << "loop: " << *L << "\n";

                for (auto &BB : L->getBlocks()) {
                    for (Instruction &I : *BB) {
                        if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                            if (CI->getCalledFunction()) { // direct call
                                string FName = CI->getCalledFunction()->getName();
                                errs() << "CalledFunciton: " << FName << "\n";
                                for (auto item : libc_input) {
                                    if (FName.find(item) != FName.npos) {
                                        // common false positive check
                                        if (FName.find("write") != FName.npos || FName.find("dir") != FName.npos || FName.find("file") != FName.npos || FName.find("name") != FName.npos || FName.find("conf") != FName.npos) continue;
                                        if (FName == "read") {
                                            if (ConstantInt *ConstVal = dyn_cast<llvm::ConstantInt>(CI->getArgOperand(2))) {
                                                if (ConstVal->getSExtValue() <= 128) {
                                                    errs() << "third arg of read is less than 128 bytes\n";
                                                    continue;
                                                }
                                            }
                                        }
                                        errs() << "potential target loop\n";
                                        // if (LoopMap.count(L) != 0 && LoopMap[L] != &F) FuncLoopToRemove.insert(&F);
                                        if (!has_loop) {
                                            LoopMap[L] = &F;
                                            has_loop = true;
                                        }
                                        else FuncLoopToRemove.insert(&F);
                                        goto check_next_loop;
                                    }
                                }
                            }
                        }
                    }
                }
                check_next_loop: ;
            }
        }
    }

    // erase the the function which has multiple input loop
    std::map<llvm::Loop *, llvm::Function *>::iterator it;
    for (it = LoopMap.begin(); it != LoopMap.end();) {
        if (FuncLoopToRemove.count(it->second) != 0) {
            LoopMap.erase(it++);
        } else it++;
    }
    errs() << "LoopMap size: " << LoopMap.size() << "\n";

    Loop *TargetLoop = NULL;
    errs() << "InputBackTrace: " << InputBackTrace << "\n";
    while (InputBackTrace.find("->") != InputBackTrace.npos && !TargetLoop) {
        string curFunName = InputBackTrace.substr(0, InputBackTrace.find("->"));
        string remainBackTrace = InputBackTrace.substr(curFunName.size() + 2, InputBackTrace.size() - curFunName.size() - 2);
        InputBackTrace = remainBackTrace;
        errs() << "curFunName: " << curFunName << "\n";
        errs() << "remainBackTrace: " << remainBackTrace << "\n";
        for (auto &item : LoopMap) {
            if (curFunName == (item.second)->getName()) {
                TargetLoop = item.first;
                errs() << "Target loop in func: " << curFunName << "\n";
                break;
            }
        }
    }
    if (!TargetLoop) {
        errs() << "can not extract target loop!\n";
        if (dumpCG) {
            dumpCallMap();
            errs() << "Finish dumpCallMap\n";
        }
        exit(1);
    }

    errs() << "TargetLoop: " << *TargetLoop << "\n";
    errs() << "FuncName: " << LoopMap[TargetLoop]->getName() << "\n";
    Ctx->TargetLoop = TargetLoop;
    RES_REPORT("\n[End of LoopCollect]\n");
}

void CallGraphPass::SVCollect(bool SkipLoopCollect, string SVStartFunc) {
    RES_REPORT("\n[SVCollect]\n");
    queue<llvm::Function *> funcQueue;
    llvm::Function *curFun;
    StringRef FName;
    strset SIdToRemove;
    if (!SkipLoopCollect && SVStartFunc == "null") {
        bool in_loop = true;
        while (!funcQueue.empty() || in_loop) {
            LIdset.clear();
            SIdset.clear();
            IdInstMap SIdInstMap;
            IdInstMap LIdInstMap;
            if (in_loop) {
                errs() << *(Ctx->TargetLoop) << "\n";
                FName = StringRef("StartLoop");
                for (auto &BB : Ctx->TargetLoop->getBlocks()) {
                    SVCollectInBB(BB, FName, funcQueue, SIdInstMap, LIdInstMap, SIdToRemove);
                }
                in_loop = false;
            } else {
                curFun = funcQueue.front();
                FName = StringRef(curFun->getName());
                funcQueue.pop();
                for (BasicBlock &BB : *curFun) {
                    SVCollectInBB(&BB, FName, funcQueue, SIdInstMap, LIdInstMap, SIdToRemove);
                }
            }
            if (LIdset.size() > 0) { // ensure LIdset not empty
                Diag << "insert LIdset to LIdMap, LIdset.size() = " << LIdset.size() << "\n";
                LIdMap.insert({FName, LIdset});
                LInstMap.insert({FName, LIdInstMap});
            }
            if (SIdset.size() > 0) { // ensure LIdset not empty
                Diag << "insert SIdset to SIdMap, SIdset.size() = " << SIdset.size() << "\n";
                SIdMap.insert({FName, SIdset});
                SInstMap.insert({FName, SIdInstMap});
            }
        }
    } else if (SVStartFunc != "null") {
        // get the SVStartFunc
        funcQueue.push(Ctx->Funcs[StringRef(SVStartFunc)]);
        while (!funcQueue.empty()) {
            LIdset.clear();
            SIdset.clear();
            IdInstMap SIdInstMap;
            IdInstMap LIdInstMap;
            curFun = funcQueue.front();
            FName = StringRef(curFun->getName());
            funcQueue.pop();
            for (BasicBlock &BB : *curFun) {
                SVCollectInBB(&BB, FName, funcQueue, SIdInstMap, LIdInstMap, SIdToRemove);
            }
            if (LIdset.size() > 0) { // ensure LIdset not empty
                Diag << "insert LIdset to LIdMap, LIdset.size() = " << LIdset.size() << "\n";
                LIdMap.insert({FName, LIdset});
                LInstMap.insert({FName, LIdInstMap});
            }
            if (SIdset.size() > 0) { // ensure LIdset not empty
                Diag << "insert SIdset to SIdMap, SIdset.size() = " << SIdset.size() << "\n";
                SIdMap.insert({FName, SIdset});
                SInstMap.insert({FName, SIdInstMap});
            }
        }
    } else {
        errs() << "Skip loop collect and not specify SV scanning start func, exit.\n";
        exit(1);
    }

    // for (auto &var : Vmap) {
    //     Diag << "var: " << var.first << ", size: " << var.second.size() << "\n";
    //     for (auto &val : var.second) {
    //         Diag << "val: " << val.first << ", count: " << val.second << "\n";
    //     }
    //     if (var.second.size() > 30) SIdToRemove.insert(var.first);
    //     if (var.second.size() == 1 && !Vmap[var.first].count(1)) SIdToRemove.insert(var.first);
    //     if (var.second.size() == 2 && !(Vmap[var.first].count(0) && Vmap[var.first].count(1)))
    //         SIdToRemove.insert(var.first);
    //     if (Vmap[var.first].count(0) && Vmap[var.first][0] != 1) SIdToRemove.insert(var.first);
    // }

    for (auto &rmsid : SIdToRemove) {
        Diag << rmsid << "\n";
        for (const auto &sm : SIdMap) {
            if (sm.second.count(rmsid) != 0) {
                SIdMap[sm.first].erase(rmsid);
                SInstMap[sm.first].erase(rmsid);
                Vmap.erase(rmsid);
            }
        }
    }

    Diag << "final SV" << "\n";
    for (auto &var : Vmap) {
        Diag << "var: " << var.first << ", size: " << var.second.size() << "\n";
        for (auto &val : var.second) {
            Diag << "val: " << val.first << ", count: " << val.second << "\n";
        }
    }

    RES_REPORT("\n[End of SVCollect]\n");
}

void CallGraphPass::SVCollectInBB(BasicBlock *BB, StringRef FName,
                                  queue<llvm::Function *> &funcQueue,
                                  IdInstMap &SIdInstMap,
                                  IdInstMap &LIdInstMap,
                                  strset &SIdToRemove) {
    errs() << "-------------\nBasicBlock in " << FName << "\n";
    std::string PRE_LID;
    for (Instruction &I : *BB) {
        if (LoadInst *L = dyn_cast<LoadInst>(&I)) {
            std::string LId = getLoadId(L);
            if (LId.find("struct.thread_info,") != LId.npos)
                continue;
    #ifdef DEBUG
            Diag << "\n" << "LoadInst:  " << *L << "\n";
            Diag << FName << " : LId-" << ":  " << LId << "\n";
    #endif
            // check is struct and global variables
            if ((LId[0] == 's' && LId[1] == 't' && LId[2] == 'r' && LId[3] == 'u' && LId[4] == 'c' && LId[5] == 't' && LId[6] == '.') || (LId[0] == 'v' && LId[1] == 'a' && LId[2] == 'r' && LId[3] == '.')) {
                std::string op_name_str;
                llvm::raw_string_ostream rso(op_name_str);
                rso << *(L->getPointerOperand());
                op_name_str = op_name_str.substr(0, op_name_str.find(" ="));
                Type *type = L->getPointerOperandType()->getContainedType(0);
                Diag << "[+] Found Id: " << LId 
                     << " | Load pointer value: " << op_name_str 
                     << " | Type: " << *type << "\n";
                if (!type->isIntegerTy()) {
                    Diag << "Not Integer Type, skip\n";
                    continue;
                }
                if (LId.find("struct.") == 0) {
                    size_t pos1 = LId.find(".");
                    size_t pos2 = LId.find(",");
                    string struct_type = LId.substr(pos1 + 1, pos2 - pos1 - 1);
                    Diag << "struct type: " << struct_type << "\n";
                    if (glibc_struct.count(struct_type) != 0) {
                        Diag << "glibc struct, skip\n";
                        continue;
                    } else {
                        Diag << struct_type << " not in glibc struct\n";
                    }
                }
                // PreLIdset.insert(LId);
                if (LIdset.insert(LId).second) LIdInstMap[LId] = L;
                gLIdset.insert(LId);
                PRE_LID = LId;
            }
        } else if (StoreInst *S = dyn_cast<StoreInst>(&I)) {
            std::string SId = getStoreId(S);
            if (SId.find("struct.thread_info,") != SId.npos)
                continue;
    #ifdef DEBUG
            Diag << "\n" << "StoreInst:  " << *S << "\n";
            Diag << FName << " : SId-" << ":  " << SId << "\n";
    #endif
            // check is struct and global variables
            if ( (SId[0] == 's' && SId[1] == 't' && SId[2] == 'r' && SId[3] == 'u' && SId[4] == 'c' && SId[5] == 't' && SId[6] == '.') || (SId[0] == 'v' && SId[1] == 'a' && SId[2] == 'r' && SId[3] == '.')) {
                std::string op_name_str;
                llvm::raw_string_ostream rso(op_name_str);
                rso << *(S->getPointerOperand());
                op_name_str = op_name_str.substr(0, op_name_str.find(" ="));
                Type *type = S->getPointerOperandType()->getContainedType(0);
                Diag << "[+] Found Id: " << SId 
                     << " | Store pointer value: " << op_name_str 
                     << " | Type: " << *type << "\n";
                
                // have been added to the remove list
                if (SIdToRemove.count(SId)) continue;

                // only consider int type variable
                if (!type->isIntegerTy()) {
                    Diag << "Not Integer Type, skip\n";
                    SIdToRemove.insert(SId);
                    continue;
                }
                // only consider const int store
                Value *val = S->getValueOperand();
                if (!dyn_cast<llvm::ConstantInt>(val)) {
                    Diag << "Not ConstantInt\n";
                    SIdToRemove.insert(SId);
                    continue;
                }
                ConstantInt *constval = dyn_cast<llvm::ConstantInt>(val);
                if (constval->isMinusOne() || constval->getSExtValue() > 100) {
                    Diag << "ConstantInt is -1 or too large (indicates line number)\n";
                    SIdToRemove.insert(SId);
                    continue;
                }

                if (SId.find("struct.") == 0) {
                    size_t pos1 = SId.find(".");
                    size_t pos2 = SId.find(",");
                    string struct_type = SId.substr(pos1 + 1, pos2 - pos1 - 1);
                    if (glibc_struct.count(struct_type) != 0) {
                        Diag << "glibc struct, skip\n";
                        continue;
                    } else {
                        Diag << SId << " not in glibc struct\n";
                    }
                }
                if (SId == PRE_LID) {
                    LIdset.erase(PRE_LID);
                    LIdInstMap.erase(PRE_LID);
                    gLIdset.erase(PRE_LID);
                } else {
                    if (SIdset.insert(SId).second) SIdInstMap[SId] = S;
                    gSIdset.insert(SId);
                }
                Vmap[SId][constval->getSExtValue()]++;
            }
        }
        else if (CallInst *C = dyn_cast<CallInst>(&I)) {
            if (Ctx->Callees.count(C)) {
                Diag << *C << " has callee:\n";
                FuncSet &FSet = Ctx->Callees[C];
                for (Function *F : FSet) {
                    Diag << F->getName() << "\n";
                    if (AnalyzedFunc.count(F) == 0) {
                        AnalyzedFunc.insert(F);
                        funcQueue.push(F);
                    }
                }
            }
        }
    }
    errs() << "-------------\n";
}
