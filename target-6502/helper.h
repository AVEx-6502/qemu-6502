#include "def-helper.h"


// Helpers for fake test instructions
#ifdef DEBUG_6502
DEF_HELPER_1(printchar, void, i32)
DEF_HELPER_0(getchar, tl)
DEF_HELPER_1(printnum, void, i32)
DEF_HELPER_0(getnum, tl)
DEF_HELPER_0(shutdown, void)
DEF_HELPER_2(printstuff, void, i32, i32)
#endif



DEF_HELPER_2(excp, void, int, int)

#include "def-helper.h"
