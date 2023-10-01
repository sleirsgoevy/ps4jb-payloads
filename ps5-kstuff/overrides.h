/* disable use of POSIX functions */
#undef __linux__
#undef __unix__

/* disable XMM intrinsics */
#undef __x86_64__

/* for BearSSL */
#define BR_64 1
#define BR_INT128 1

/* for libtomcrypt */
#define ARGTYPE 3
#define TAB_SIZE 1
#define LTC_NO_TEST 1
