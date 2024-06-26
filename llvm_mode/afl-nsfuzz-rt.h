#pragma once
#ifndef _NO_NSFUZZ_IN_ASM
#if defined(__cplusplus)
extern "C" {
#endif

#ifdef _NSFUZZ_PARSING
#define _NSFUZZ_STATE(x) x __attribute__((annotate("NSFUZZ_STATE")))
#else
#define _NSFUZZ_STATE(x) x
#endif

#define _NSFUZZ_SYNC() raise(SIGSTOP)

#if defined(__cplusplus)
}
#endif
#endif
