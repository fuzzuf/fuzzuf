# libFuzzer Implementation in fuzzuf

This section describes the implementation of libFuzzer in fuzzuf.

## How to Construct the Standard libFuzzer

The fuzzer corresponding to `Fuzzer::Loop()` of the original libFuzzer is `createRunone()` in [include/fuzzuf/algorithms/libfuzzer/create.hpp](/include/fuzzuf/algorithms/libfuzzer/create.hpp). You can use the libFuzzer implementation in fuzzuf by using this function when you use it as a standard libFuzzer.

## HierarFlow Nodes for libFuzzer Implementation

fuzzuf has the following nodes to represent libFuzzer in HierarFlow. For more details about each node, refer to the comments in the source code or the documentation generated by Doxygen.

### Mutator Nodes

* [EraseBytes](/include/fuzzuf/algorithms/libfuzzer/mutation/erase_bytes.hpp)
* [InsertByte](/include/fuzzuf/algorithms/libfuzzer/mutation/insert_byte.hpp)
* [InsertRepeatedBytes](/include/fuzzuf/algorithms/libfuzzer/mutation/insert_repeated_bytes.hpp)
* [ChangeByte](/include/fuzzuf/algorithms/libfuzzer/mutation/change_byte.hpp)
* [ChangeBit](/include/fuzzuf/algorithms/libfuzzer/mutation/change_bit.hpp)
* [ShuffleBytes](/include/fuzzuf/algorithms/libfuzzer/mutation/shuffle_bytes.hpp)
* [ChangeASCIIInteger](/include/fuzzuf/algorithms/libfuzzer/mutation/change_ascii_integer.hpp)
* [ChangeBinaryInteger](/include/fuzzuf/algorithms/libfuzzer/mutation/change_binary_integer.hpp)
* [CopyPart](/include/fuzzuf/algorithms/libfuzzer/mutation/copy_part.hpp)
  * CopyPartOf
  * InsertPartOf
* [CrossOver](/include/fuzzuf/algorithms/libfuzzer/mutation/crossover.hpp)
  * CrossOver
  * CopyPartOf
  * InsertPartOf
* [Dictionary](/include/fuzzuf/algorithms/libfuzzer/mutation/dictionary.hpp)
  * Dictionary
  * UpdateDictionary

### Control Nodes

The control node performs the control necessary to construct the libFuzzer in HierarFlow.

* [ForEach](/include/fuzzuf/algorithms/libfuzzer/hierarflow/for_each.hpp)
* [IfNewCoverage](/include/fuzzuf/algorithms/libfuzzer/hierarflow/if_new_coverage.hpp)
* [RandomCall](/include/fuzzuf/algorithms/libfuzzer/hierarflow/random_call.hpp)
* [Repeat](/include/fuzzuf/algorithms/libfuzzer/hierarflow/repeat.hpp)
* [RepeatUntilNewCoverage](/include/fuzzuf/algorithms/libfuzzer/hierarflow/repeat_until_new_coverage.hpp)
* [RepeatUntilMutated](/include/fuzzuf/algorithms/libfuzzer/hierarflow/repeat_until_mutated.hpp)
* [DoNothing](/include/fuzzuf/algorithms/libfuzzer/do_nothing.hpp)
* [Assign](/include/fuzzuf/algorithms/libfuzzer/hierarflow/assign.hpp)
* [Append](/include/fuzzuf/algorithms/libfuzzer/hierarflow/append.hpp)

### Execute Node

The Execute node has an Executor, which executes the target with input values and gets coverage, standard output, and execution results.

* [Execute](/include/fuzzuf/algorithms/libfuzzer/hierarflow/execute.hpp)

### Feedback Node

Feedback nodes are responsible for selecting execution results to be added to the corpus.

* [CollectFeatures](/include/fuzzuf/algorithms/libfuzzer/hierarflow/collect_features.hpp)
* [AddToCorpus](/include/fuzzuf/algorithms/libfuzzer/hierarflow/add_to_corpus.hpp)
* [AddToSolutions](/include/fuzzuf/algorithms/libfuzzer/hierarflow/add_to_solution.hpp)
* [UpdateDistribution](/include/fuzzuf/algorithms/libfuzzer/hierarflow/add_to_solution.hpp)
* [ChooseRandomSeed](/include/fuzzuf/algorithms/libfuzzer/hierarflow/choose_random_seed.hpp)

### Debug Nodes

Debug nodes make it easy to debug fuzzers in HierarFlow.

* [Dump](/include/fuzzuf/algorithms/libfuzzer/hierarflow/dump.hpp)
* [PrintStatusForNewUnit](/include/fuzzuf/algorithms/libfuzzer/hierarflow/print_status_for_new_unit.hpp)

## Unimplemented Features

Some features of libFuzzer are unimplemented in fuzzuf:

### Mutator

#### Mutate_AddWordFromTORC (CMP)

The original libFuzzer adds this mutator when option CMP is enabled. It records the information of branching by comparison operations and performs mutation.
If the compiler has the `-fsanitize-coverage=trace-cmp` option, the compiler will instrument the executable to record the comparison target and operator type at runtime when the executable branches on a comparison operation. CMP will look for a value in the input that is the same as the value used in the comparison and rewrites it so that the conditional branch goes into a different side. This mutation is based on the following idea: even if the input has the same value as the value used in the comparison, it does not guarantee the same value as the comparison target, but the fuzzer expects to change the branch direction with some probability.
This mutator is unimplemented in fuzzuf because it does not support `trace-cmp` to get information about comparison operations.

#### Mutate_AddWordFromPersistentAutoDictionary

libFuzzer has a dictionary that stores the values inserted by `Mutate_AddWordFromManualDictionary` and `Mutate_AddWordFromTORC` that led to the discovery of new coverage. Since CMP is unimplemented in fuzzuf, this mutator only stores input from `Mutate_AddWordFromManualDictionary`.

#### Custom Mutator

libFuzzer provides CustomMutator and CustomCrossOver to add your mutators. fuzzuf does not provide nodes for these mutators because it is easier to add nodes by yourself than provide special nodes.

### Corpus

libFuzzer can persist the complete state of corpus and resume fuzzing. Still, the implementation of fuzzuf only persists the input values, so it cannot completely restore the previous state even if it resumes from the persistent information.

### Feature

#### Data Flow Trace

Data Flow Trace uses a record of data movement obtained using LLVM's DataFlowSanitizer to determine which parts of the input values affect the branch. By masking the range of mutation based on this result, a fuzzer can concentrate on finding the input that exits a particular branch. However, the original implementation of libFuzzer does not use this information effectively to generate the mask.
This feature is not implemented in fuzzuf because there is no way to get the information equivalent to DataFlowSanitizer similar to CMP.

### Executor

#### Avoiding Child Process Creation

libFuzzer avoids the cost of creating child processes by linking the fuzzing target and the fuzzer into the same binary. Still, since there is no equivalent executor in fuzzuf, the implementation of fuzzuf creates child processes.

#### Support for Shared Libraries

libFuzzer has a mechanism to collect and combine the edge coverage of both executable binaries and shared libraries linked to them. This feature is not implemented in fuzzuf because there is no way to get coverage from shared libraries.

### Feedback

#### Leak Sanitizer

The original libFuzzer detects memory leaks. On the other hand, fuzzuf can treat this case as a failure if the target is compiled with Leak Sanitizer. Still, since the reason for the failure is abort, it is not possible to determine whether it was a memory leak or not, so fuzzuf cannot use the information of unreleased memory detection.

#### Stack Depth Tracing

The original libFuzzer uses the stack-depth of LLVM's SanitizerCoverage to get the stack depth used by the target, but fuzzuf has no way to get the stack depth used, so it is unimplemented.
