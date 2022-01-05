# fuzzuf

[![Build Status](https://jenkins.atla.ricsec.co.jp/buildStatus/icon?job=fuzzuf-branch_build)](https://jenkins.atla.ricsec.co.jp/view/fuzzuf/job/fuzzuf-branch_build/)

![fuzzuf-afl-exifutil](/docs/resources/img/fuzzuf-afl-exifutil.png)

[README（日本語）](/README_ja.md)

**fuzzuf** (**fuzz**ing **u**nification **f**ramework) is a fuzzing framework with its own DSL to describe a fuzzing loop by constructing building blocks of fuzzing primitives.

For build instructions and a tutorial, please follow [the TUTORIAL.md](/TUTORIAL.md).

## Why use fuzzuf?

fuzzuf enables a flexible definition of a fuzzing loop defined in each fuzzer by describing it as combinations of building blocks with DSL notations while keeping extensibility for its original fuzzer.
It already has various fuzzer implementations including AFL, VUzzer, and libFuzzer that can be further extended by users.

## Benefits of using fuzzuf

There are mainly four advantages of writing fuzzers on fuzzuf framework:  

- Can describe a fuzzing loop with combinations of each fuzzing primitive  
fuzzuf constructs a fuzzing loop with a combination of fuzzing primitives (an individual step in a fuzzing loop) like building blocks. Since each block can be appended, removed, replaced, and resuable, fuzzuf can keep the high modularity of every fuzzing loop defined. 

- A flexible, user-definable fuzzing loops  
Since existing fuzzing frameworks tend to have fixed, or hard-coded fuzzing loops inside the frameworks themselves, their users could not manipulate their behaviors.
fuzzuf can assign and implement a routine for each fuzzing primitive divided, and describe and modify the structure of a fuzzing loop as a user wants.

- Easy to compare a derived fuzzer to its original  
It is not rare that fuzzing researchers and enthusiasts fork an existing fuzzer to implement their own idea on top of it. As a matter of fact, a lot of academic works have showcased numerous AFL-based fuzzers reflecting their idea. By leveraging fuzzuf DSL's building block-like characteristics and reusing existing fuzzing primitives, users can highly accelerate their new fuzzer's development process. 
Moreover, by comparing diffs of DSLs between the original fuzzer and its derivatives, the enhancements can smoothly be spotted at a glance (not only for users themselves, but also for reviewers and other researchers).

- AFL fuzzer as a template  
On fuzzuf, AFL is available as a fuzzer (C\+\+) template as well. This means that the cost to implement and review a new or existing AFL-based fuzzer has been lowered a lot by utilizing it. For example, fuzzuf's AFLFast is built upon this template. Only a few modifications in routines and a struct which records a fuzzer state are required to change, and it keeps its original's flow unchanged.

## HierarFlow

fuzzuf utilizes its own DSL called **HierarFlow** for fuzzing loop statements. It is implemented on top of a C++ language with the grammar made to look like a tree structure to describe a fuzzing loop as a combination of building blocks. 

With HierarFlow, we can write both existing and new fuzzers in a neat and tidy way, as the structure of a fuzzing loop can clearly be shown. For instance, we can divide an AFL fuzzer (which has already been implemented on fuzzuf as a template!) into multiple fuzzing primitives that include *PUT executor*, *mutators* (both deterministic and random), *dictionary updater*, and so on. Users can implement each primitive in C++ code and connect them together with HierarFlow's operator to eventually construct a fuzzing loop of a fuzzer they want to achieve. 

The document for HierarFlow will be added soon.

## List of Available Fuzzers

fuzzuf comes with the following fuzzers implemented by default. To see the overview and how to them from CLI, please follow the links provided below.  
Note, when using fuzzuf from CLI, you have to separate global options (options available for all fuzzers) and local options (fuzzer specific options) with `--`. 

### AFL

A re-implementation of a general purpose fuzzer, representing a CGF (Coverage-guided Greybox Fuzzer). Also available as a template for its derivatives.  
This implementation has consistency and greater execution speed compared to its original, as showed in [fuzzuf/fuzzuf-afl-artifact](https://github.com/fuzzuf/fuzzuf-afl-artifact).

- [Introduction and how to use in CLI](/docs/algorithms/AFL/algorithm_en.md)

### AFLFast

An implementation of AFLFast, utilizing an AFL template described above. The algorithm tries to increase its performance by manipulating the power schedule. 

- [Introduction and how to use in CLI](/docs/algorithms/AFLFast/algorithm_en.md)

### VUzzer

A mutation-based fuzzer guess data structures by analyzing the PUT control flow and the data flow.  
The original VUzzer used libdft64 for data flow analysis, which does not meet our requirements in a modern environment. Therefore, fuzzuf instead uses a modified version of [PolyTracker](https://github.com/fuzzuf/polytracker).

- [Introduction and how to use in CLI](/docs/algorithms/VUzzer/algorithm_en.md)

### libFuzzer

CGF included in the LLVM project's compiler-rt libraries.

- [Introduction and how to use in CLI](/docs/algorithms/libFuzzer/manual.md)

### Nezha

A fuzzer originates from libFuzzer that tries to find defects in the program by executing programs having different implementations with the same input and compares its execution results.  
It shows that differential fuzzing algorithms like Nezha can also be implemented on fuzzuf.

- [Introduction and how to use in CLI](/docs/algorithms/Nezha/manual.md)

## License

fuzzuf is licensed under the GNU Affero General Public License v3.0. Some codes originate from external projects are licensed under their own licenses. Please refer to [LICENSE](/LICENSE) for details.

## Acknowledgements

This project has received funding from the Acquisition, Technology & Logistics Agency (ATLA) under the Innovative Science and Technology Initiative for Security 2020 (JPJ004596).

