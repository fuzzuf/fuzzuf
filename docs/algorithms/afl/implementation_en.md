# AFL Implementation in fuzzuf

## Reference AFL Implementation

- Version: 2.57b
- Commit: [fab1ca5ed7e3552833a18fc2116d33a9241699bc](https://github.com/google/AFL/commit/fab1ca5ed7e3552833a18fc2116d33a9241699bc)

## Directory Layout

In fuzzuf, implementations of AFL are located in [include/fuzzuf/algorithms/afl](/include/fuzzuf/algorithms/afl) and [algorithms/afl](/algorithms/afl). Because AFL has many derived algorithms, we implemented most of the classes by templates. Therefore, the declarations and definitions of those classes are in the header files under [include/fuzzuf/algorithms/afl](/include/fuzzuf/algorithms/afl).

These template classes are declared in [include/fuzzuf/algorithms/afl](/include/fuzzuf/algorithms/afl) and defined in [include/fuzzuf/algorithms/afl/templates](/include/fuzzuf/algorithms/afl/templates). This directory layout is due to historical reasons and not due to the coding conventions of fuzzuf; it was designed to reduce the difference of changes when the AFL implementation was reconstructed as template classes to improve reusability. We consider removing the `templates` subdirectory and merging the files in future refactorings.

## AFL in HierarFlow

AFL is represented in HierarFlow as in [include/fuzzuf/algorithms/afl/templates/afl_fuzzer.hpp](/include/fuzzuf/algorithms/afl/templates/afl_fuzzer.hpp):

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

The following code implements the routines for each node:

- Mutation node routines (e.g. `bit_flip1` and `bit_flip_other`):
  - [include/fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp](/include/fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp)
- Update node routines (e.g. `normal_update` and `construct_auto_dict`):
  - [include/fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp](/include/fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp)
- Other node routines:
  - [include/fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp](/include/fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp)

## Consistency

The AFL of fuzzuf has been confirmed to be identical in behavior to the original implementation, which means that it is fully consistent. For more details on consistency testing, please check the following repository:

- [https://github.com/fuzzuf/fuzzuf-afl-artifact](https://github.com/fuzzuf/fuzzuf-afl-artifact)

### Changes after Consistency Test

The current implementation has changed significantly from the implementation at the time of the consistency check. One of the most notable changes is the customizable design of the mutation havoc to facilitate the implementation of AFL-derived algorithms. As a result, the current AFL on fuzzuf does not produce the same results as the original AFL.

However, since there is no difference in the mutations themselves, and the probability of each type of mutation being selected in havoc should be the same as in the original AFL, the statistical behavior should not have changed at all.

## How to Implement an AFL Derived Algorithm

Many users may want to use fuzzuf to implement AFL-derived algorithms.
Here is a quick overview of how to implement an AFL-derived algorithm. Please refer to AFLFast Implementation for the detailed implementation.

### 1. Define a Tag

First of all, define an empty structure called Tag for the derived algorithm you want to create (e.g., `struct AFLDerivedTag {};`).
For example, the Tag for AFL is defined in [include/fuzzuf/algorithms/afl/afl_option.hpp](/include/fuzzuf/algorithms/afl/afl_option.hpp):

```cpp
struct AFLTag {};
```

In fuzzuf, Tag allows you to arbitrarily change the value of a constant. See the comments in [include/fuzzuf/algorithms/afl/afl_option.hpp](/include/fuzzuf/algorithms/afl/afl_option.hpp) for details.

### 2. Inherit AFLTestcase

If you want a seed to have its information in addition to what AFL has, define a new Testcase class that inherits from `AFLTestcase` (e.g. `AFLDerivedTestcase`). You should declare `AFLDerivedTestcase::Tag` using an alias declaration with `using`. For example, the code can look like this:

```cpp
struct AFLDerivedTestcase : public AFLTestcase {
  using Tag = AFLDerivedTag;

  ...
```

### 3. Inherit AFLState

If you want additional information in the whole algorithm, define a new State class that inherits from `AFLState` (e.g. `AFLDerivedState`).

### 4. Specialize AFLState Member Functions and/or Add a HierarFlowRoutine

If the derived algorithm has the same algorithm flow as AFL but needs to be handled differently, use member function overrides or template class specialization.

Alternatively, if the derived algorithm has a different algorithm flow from AFL, define a HierarFlowRoutine that corresponds to the processing. In this case, define `AFLFuzzerTemplate<AFLDerivedState>::BuildFuzzFlow` and describe the algorithm flow.
