# fuzzuf

[![Build Status](https://jenkins.atla.ricsec.co.jp/buildStatus/icon?job=fuzzuf-branch_build)](https://jenkins.atla.ricsec.co.jp/view/fuzzuf/job/fuzzuf-branch_build/)

[README（日本語）](/README_ja.md)

**fuzzuf** (**fuzz**ing **u**nification **f**ramework) is a fuzzing framework with its own DSL to describe a fuzzing loop by constructing building blocks of fuzzing primitives.

For build instructions and a tutorial, please follow [the TUTORIAL.md](/TUTORIAL.md).

## Why use fuzzuf?

fuzzuf enables a flexible definition of a fuzzing loop defined in each fuzzer by describing it as combinations of building blocks with DSL notations while keeping extensibility for its original fuzzer.
It already has various fuzzer implementations including AFL, VUzzer, and libFuzzer that can be further extended by users.

## HierarFlow

fuzzuf utilizes its own DSL called **HierarFlow** for fuzzing loop statements. It is implemented on top of a C++ language with the grammar made to look like a tree structure to describe a fuzzing loop as a combination of building blocks. 

With HierarFlow, we can write both existing and new fuzzers in a neat and tidy way, as the structure of a fuzzing loop can clearly be shown. For instance, we can divide an AFL fuzzer (which has already been implemented on fuzzuf as a template!) into multiple fuzzing primitives that include *PUT executor*, *mutators* (both deterministic and random), *dictionary updater*, and so on. Users can implement each primitive in C++ code and connect them together with HierarFlow's operator to eventually construct a fuzzing loop of a fuzzer they want to achieve. 

### Example: AFL in HierarFlow

[The following short snippet](/include/fuzzuf/algorithms/afl/templates/afl_fuzzer.hpp) represents AFL in HierarFlow:

```cpp
    fuzz_loop << (
         cull_queue
      || select_seed
    );

    select_seed << (
         consider_skip_mut
      || retry_calibrate
      || trim_case
      || calc_score
      || apply_det_muts << (
             bit_flip1 << execute << (normal_update || construct_auto_dict)
          || bit_flip_other << execute.HardLink() << normal_update.HardLink()
          || byte_flip1 << execute.HardLink() << (normal_update.HardLink()
                                               || construct_eff_map)
          || byte_flip_other << execute.HardLink() << normal_update.HardLink()
          || arith << execute.HardLink() << normal_update.HardLink()
          || interest << execute.HardLink() << normal_update.HardLink()
          || user_dict_overwrite << execute.HardLink() << normal_update.HardLink()
          || auto_dict_overwrite << execute.HardLink() << normal_update.HardLink()
         )
       || apply_rand_muts << (
               havoc << execute.HardLink() << normal_update.HardLink()
            || splicing << execute.HardLink() << normal_update.HardLink()
          )
       || abandon_node
    );
```

This simply shows how flexible and powerful HierarFlow is. Please refer to the [document](/docs/hierarflow_en.md) for more details.

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

## List of Currently Available Fuzzers

fuzzuf comes with the following fuzzers implemented by default. To see the overview and how to them from CLI, please follow the links provided below.  
Note, when using fuzzuf from CLI, you have to separate global options (options available for all fuzzers) and local options (fuzzer specific options) with `--`. 

|Fuzzer|Type|Description|CLI Usage|Algorithm Overview|
|---|---|---|---|---
|AFL|Greybox|A re-implementation of general purpose fuzzer, representing a CGF. Also available as a template for its derivatives.|[How to use fuzzuf's AFL CLI](/docs/algorithms/afl/algorithm_en.md#how-to-use-fuzzufs-afl-cli)|[Algorithm Overview](/docs/algorithms/afl/algorithm_en.md#algorithm-overview)
|AFLFast|Greybox|An implementation of AFLFast, utilizing an AFL template.<br/>The algorithm tries to increase its performance by manipulating the power schedule.|[CLI Usage](/docs/algorithms/aflfast/algorithm_en.md#cli-usage)|[Algorithm Overview](/docs/algorithms/aflfast/algorithm_en.md#algorithm-overview)
|VUzzer|Greybox|A mutation-based fuzzer guess data structures by analyzing the PUT control flow and the data flow.|Read [Prerequisite](/docs/algorithms/vuzzer/algorithm_en.md#prerequisite) first, then [Usage on CLI](docs/algorithms/vuzzer/algorithm_en.md#usage-on-cli)|[Algorithm Overview](/docs/algorithms/vuzzer/algorithm_en.md#algorithm-overview)
|libFuzzer|Greybox|CGF included in the LLVM project's compiler-rt libraries.|[How to use libFuzzer on fuzzuf](/docs/algorithms/libfuzzer/manual.md#how-to-use-libfuzzer-on-fuzzuf)|[What is libFuzzer?](/docs/algorithms/libfuzzer/algorithm_en.md#what-is-libfuzzer)
|Nezha|Greybox|A fuzzer originates from libFuzzer that tries to find defects in the program by executing programs having different implementations with the same input and compares its execution results (differential fuzzing).|[How to use Nezha on fuzzuf](/docs/algorithms/nezha/manual.md#how-to-use-nezha-on-fuzzuf)|TBD
|DIE|Greybox|A fuzzer for JavaScript engines preserving the aspect of the test cases through the mutation process|[Usage on CLI](/docs/algorithms/die/algorithm_en.md#usage-on-cli)|[Overview of Algorithm](/docs/algorithms/die/algorithm_en.md#overview-of-algorithm)

## Why not Rust?

We have considered migrating the framework from C\+\+ to Rust because it is safer and has a neat ecosystem during development. However, despite the attempts and the discussions, we concluded that we would not switch the language. The reason why is explained in detail [here](/docs/why_we_didnt_move_to_rust_en.md).

## API Reference

API reference generated by doxygen is available [here](https://fuzzuf.github.io/fuzzuf-doxygen-docs/).

## License

fuzzuf is licensed under the GNU Affero General Public License v3.0. Some codes originate from external projects are licensed under their own licenses. Please refer to [LICENSE](/LICENSE) for details.

## Acknowledgements

This project has received funding from the Acquisition, Technology & Logistics Agency (ATLA) under the Innovative Science and Technology Initiative for Security 2020 (JPJ004596).

