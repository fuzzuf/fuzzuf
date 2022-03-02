# IJON

## What is IJON?

IJON is an annotation mechanism that allows PUTs to return new types of feedback to fuzzers, and a fuzzer that supports those feedbacks, proposed by SysSec. Many famous fuzzers are classified as coverage-guided fuzzers, which try to find new behaviors in a program by receiving code coverage as feedback from PUTs. A typical coverage-guided fuzzer has the following weaknesses: 

- They do not care about the order in which the code coverage was obtained. For example, suppose there is a bug whose triggering condition is "function B must be executed immediately after function A is executed". Because the fuzzer cannot distinguish between the input that causes the bug and the input that causes the execution of function A after the execution of function B, it may try only the latter and overlook the bug. More to the point, many algorithms cannot distinguish between "input that causes both function A and function B to be called" and "a set of input that causes function A to be called and input that causes function B to be called" in the first place, and if one of the two is already tested, the other won't be tested.
  - Among the types of code coverage, path coverage can deal with this problem to some extent. However, there is a trade-off in that if a fuzzer over-stores inputs with different execution paths, it is more likely to retain similar inputs that result in the same fuzzing result, and the overall efficiency of a fuzzing campaign will be reduced. It is difficult to automatically adjust this trade-off to a good degree.
- There can be internal state changes that cannot be noticed by code coverage. For example, as described in IJON's paper, consider the coordinates of the player in a game. The position of the player on the screen is likely to be important in discovering new states of the game. If the player is in the upper-left corner of the screen, he may be closer to the coordinates of the new event than if in the lower right corner of the screen. However, if only code coverage is used as feedback, the same feedback will be returned regardless of which coordinate the player is at.

IJON proposes a simple solution to these problems: human annotation on PUTs. When building a PUT from source code and instrumenting it to obtain coverage, humans can add annotations to the source code to customize the feedback that the PUT gives to a fuzzer. There are various annotations provided by IJON that humans can use to specify what they consider to be important internal states. For example, annotations such as "record the maximum value of a variable in the feedback" or "record the minimum difference between two variables" are possible.

In practice, because IJON is implemented based on AFL, the feedback returned by PUT is (Hashed) Edge Coverage, which is passed on to the fuzzer via shared memory. Therefore, the annotations that can be written in the source code are specifically implemented as functions and macros that write values to the shared memory. These macros and functions are compiled together when the instrumentation tools instrument the Edge Coverage.
Thus, because IJON is an AFL-based fuzzer and has an interface for harness description required in practical fuzzing, it has been implemented on fuzzuf to improve the applicability of fuzzuf.


## How to use fuzzuf's IJON CLI

With `fuzzuf` installed, run

```bash
fuzzuf ijon -i path/to/initial/seeds/ path/to/PUT @@
```

to start IJON. The global options that can be specified are the same as for AFL.
For AFL options, see [AFL/algorithm_en.md](/docs/algorithms/afl/algorithm_en.md).

The local options for IJON that can be used are:

- `--forksrv 0|1`
  - If 1 is specified, then fork server mode is enabled. It is enabled by default.

## Algorithm Overview

IJON is implemented in a way that retains most of the functions of AFL, and adds additional functions. Roughly speaking, the differences from AFL are as follows:

- Some cases of havoc mutation have been modified.
- IJON has its own seed queue, apart from the AFL seed queue.
  - For each element of a 64-bit non-negative integer array in shared memory, the IJON seed queue saves the seed that makes a program record the largest value in the element.
- At the beginning of the fuzzing loop, the procedure branches randomly.
  - 80% of the time, a seed is selected from the IJON seed queue. In this case, it immediately moves to the havoc stage, and returns to the beginning of the fuzzing loop after a certain number of havoc mutations.
  - 20% of the time, a seed is selected from the AFL seed queue. In this case, mutation is performed in the same flow as the original AFL.
- After a PUT is executed, the IJON seed queue is updated based on the feedback obtained from the PUT.
  - Even when AFL is selected in 20% probability, the IJON seed queue is also updated.
- Some of the constant values have been changed.
