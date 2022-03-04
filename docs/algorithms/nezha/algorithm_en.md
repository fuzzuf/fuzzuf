# Nezha

## What is Nezha?

[https://github.com/nezha-dt/nezha](https://github.com/nezha-dt/nezha)

Nezha is a differential fuzzer that extends LLVM's libFuzzer and is available for both greybox fuzzing and blackbox fuzzing (in fact, there is greybox fuzzing implementation only). We reimplemented Nezha as one of the use cases to show differential fuzzing implementation in fuzzuf.

Overriding parts of libFuzzer implement Nezha, so most algorithms are the same as libFuzzer. However, it differs from libFuzzer in that it executes a single input value for multiple different targets that perform the same operation and considers inputs that result in different outputs for only some targets as "inputs that exploit some implementation flaws."

Nezha performs the same process of input value selection and mutation as libFuzzer. Nezha calculates the feature and adds the corpus for each target execution.

For each target, the index of the coverage edge is set to a non-overlapping value (which is natural since the original implementation links all targets to a single binary) to prevent the results of executing different targets from being considered identical.

The corpus will contain at most the same number of "executions with exactly the same input values but with different results" as the target. Since these corpus items are individually weighted, the probability that an input value is selected is the sum of the weights of the results of executions with the same input value registered in the corpus. After executing targets, the fuzzer decides whether consider the execution results as "inputs that exploit some implementation flaws" based on the status of the corpus and the output from each target.
