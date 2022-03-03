# IJON

## What is IJON?

[IJON](https://github.com/RUB-SysSec/ijon/)[^ijon] is an annotation mechanism that allows PUTs to return new types of feedback to fuzzers, and a fuzzer that supports those feedback, proposed by [SysSec](https://informatik.rub.de/syssec/). Many famous fuzzers are classified as coverage-guided fuzzers, which try to find new behavior in a program by receiving code coverage as feedback from PUTs. A typical coverage-guided fuzzer has the following weaknesses: 

- It does not care about the order in which it obtained the code coverage. For example, suppose there is a bug whose triggering condition is "executing function B immediately after executing function A". Because the fuzzer cannot distinguish between the input that causes the bug and the one that causes the execution of function A after function B, it may try only the latter and overlook the bug. More to the point, many algorithms cannot distinguish between "the input that causes both function A and function B to be called" and "two inputs such that one of them executes only function A and the other executes only function B." If the latter two inputs are tested first, the fuzzer will not test the former one.
  - Among the types of code coverage, path coverage can deal with this problem to some extent. However, there is a trade-off in that if a fuzzer over-stores inputs with different execution paths, it is more likely to retain similar inputs that yield the same fuzzing result, which will eventually reduce the overall efficiency of a fuzzing campaign. It is difficult to adjust this trade-off automatically.
- There may be some internal state changes that the code coverage cannot reveal. For example, as described in IJON's paper, consider the coordinates of the player in a game. The position of the player on the screen is likely to be important in discovering new states of the game. If the player is in the upper-left corner of the screen, he may be closer to the coordinates of the new event than if in the lower right corner of the screen. However, if the fuzzer just uses the code coverage, both of them will produce the same feedback regardless of which coordinate the player is at.

IJON proposes a simple solution to these problems: human annotation on PUTs. When building a PUT from source code and instrumenting it to obtain coverage, humans can add annotations to the source code to customize the feedback that the PUT gives to a fuzzer. There are various annotations provided by IJON that humans can use to specify what they consider to be important internal states. For example, annotations such as "record the maximum value of a variable in the feedback" or "record the minimum difference between two variables" are possible.

In practice, because IJON's fuzzer is implemented based on AFL, the feedback returned by PUT is (Hashed) Edge Coverage, which is passed on to the fuzzer via shared memory. Therefore, the annotations that can be written in the source code are specifically implemented as functions and macros that write values to the shared memory. These macros and functions are compiled together when the instrumentation tools instrument the Edge Coverage.
Thus, because IJON has an AFL-based fuzzer and an interface for harness description required in practical fuzzing, it has been implemented on fuzzuf to improve the applicability of fuzzuf.

## How to use fuzzuf's IJON CLI

To use IJON's fuzzer, first you need to prepare annotated PUTs with instrumentation tools.
Because fuzzuf doesn't have its own instrumentation tool, please visit [IJON's repo](https://github.com/RUB-SysSec/ijon/) and build the original instrumentation tool.

After you create a PUT and install `fuzzuf`, run

```bash
fuzzuf ijon -i path/to/initial/seeds/ path/to/PUT @@
```

to start IJON's fuzzer. The global options available are the same as for AFL.
For AFL options, see [AFL/algorithm_en.md](/docs/algorithms/afl/algorithm_en.md).

The local option for IJON is:

- `--forksrv 0|1`
  - If 1 is specified, then fork server mode is enabled. It is enabled by default.

## Example Usage

You can test the original instrumentation tool and IJON's fuzzer in fuzzuf by building and fuzzing [test.c](https://github.com/RUB-SysSec/ijon/blob/master/test.c) and [test2.c](https://github.com/RUB-SysSec/ijon/blob/master/test2.c) found in IJON's repo. Note that, test.c, included in the latest commit (56ebfe34), may yield compilation errors and in that case you need to apply the following changes:

```diff
diff --git a/llvm_mode/afl-rt.h b/llvm_mode/afl-rt.h
index 616cbd8..28d5f9d 100644
--- a/llvm_mode/afl-rt.h
+++ b/llvm_mode/afl-rt.h
@@ -45,14 +45,14 @@ void ijon_enable_feedback();
 void ijon_disable_feedback();

 #define _IJON_CONCAT(x, y) x##y
-#define _IJON_UNIQ_NAME() IJON_CONCAT(temp,__LINE__)
+#define _IJON_UNIQ_NAME IJON_CONCAT(temp,__LINE__)
 #define _IJON_ABS_DIST(x,y) ((x)<(y) ? (y)-(x) : (x)-(y))

 #define IJON_BITS(x) ((x==0)?{0}:__builtin_clz(x))
 #define IJON_INC(x) ijon_map_inc(ijon_hashstr(__LINE__,__FILE__)^(x))
 #define IJON_SET(x) ijon_map_set(ijon_hashstr(__LINE__,__FILE__)^(x))

-#define IJON_CTX(x) ({ uint32_t hash = hashstr(__LINE__,__FILE__); ijon_xor_state(hash); __typeof__(x) IJON_UNIQ_NAME() = (x); ijon_xor_state(hash); IJON_UNIQ_NAME(); })
+#define IJON_CTX(x) ({ uint32_t hash = ijon_hashstr(__LINE__,__FILE__); ijon_xor_state(hash); __typeof__(x) IJON_UNIQ_NAME = (x); ijon_xor_state(hash); IJON_UNIQ_NAME; })

 #define IJON_MAX(x) ijon_max(ijon_hashstr(__LINE__,__FILE__),(x))
 #define IJON_MIN(x) ijon_max(ijon_hashstr(__LINE__,__FILE__),0xffffffffffffffff-(x))
diff --git a/test.c b/test.c
index 50b1b05..aa022f6 100644
--- a/test.c
+++ b/test.c
@@ -3,6 +3,7 @@
 #include<assert.h>
 #include<stdbool.h>
 #include <stdlib.h>
+#include <stdint.h>
```

For example, you can build test.c and fuzz the produced binary with the following commands:

```bash
$ (path_to_ijon)/llvm_mode/afl-clang-fast (path_to_ijon)/test.c -o test
$ mkdir /tmp/ijon_test_indir/ && echo hello > /tmp/ijon_test_indir/hello
$ fuzzuf ijon -i /tmp/ijon_test_indir/ ./test
```

Here, you don't need to specify `@@` in the last command because the binary receives inputs via stdin.

While test.c and test2.c gives you an idea how you can use annotations, you can check README and source code in IJON's repo to understand their further usage.

## Algorithm Overview

IJON is implemented in a way that retains most of the functions of AFL, and adds additional functions. Roughly speaking, the differences from AFL are as follows:

- Some cases of havoc mutation are modified.
- IJON has its own seed queue, apart from the AFL seed queue.
  - For each element of a 64-bit non-negative integer array in shared memory, the IJON seed queue saves the seed that made a program record the maximum value in the element.
- At the beginning of the fuzzing loop, the procedure branches randomly.
  - 80% of the time, a seed is selected from the IJON seed queue. In this case, the fuzzer immediately moves to the havoc stage, and returns to the beginning of the fuzzing loop after a certain number of havoc mutations.
  - 20% of the time, a seed is selected from the AFL seed queue. In this case, mutation is performed in the same flow as the original AFL.
- After a PUT exits, the IJON seed queue is updated based on the feedback obtained from the PUT.
  - Even when AFL is selected in 20% probability, the IJON seed queue is also updated.
- Some of the constants are changed.
