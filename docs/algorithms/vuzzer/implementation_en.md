# VUzzer Implementation in fuzzuf

## Reference VUzzer Implementation

- Version: 1.0
- Commit: [2b1b0ed757a3dca114db0192fa4ab1add92348bc](https://github.com/vusec/vuzzer64/commit/2b1b0ed757a3dca114db0192fa4ab1add92348bc)

## Directory Layout

In fuzzuf, implementations of VUzzer are located in [include/fuzzuf/algorithms/vuzzer](/include/fuzzuf/algorithms/vuzzer) and [algorithms/vuzzer](/algorithms/vuzzer).

## VUzzer in HierarFlow

VUzzer is represented in HierarFlow as in [algorithms/vuzzer/vuzzer.cpp](/algorithms/vuzzer/vuzzer.cpp):

```cpp
    fuzz_loop <<
        decide_keep <<
        run_ehb << (
            execute << update_fitness << trim_queue
        ||  execute_taint << update_taint
        ||  mutate
        ||  update_queue
        );
```

The following code implements the routines for each node:

- Mutation node routines (e.g. `mutate`):
  - [include/fuzzuf/algorithms/vuzzer/vuzzer_mutation_hierarflow_routines.hpp](/include/fuzzuf/algorithms/vuzzer/vuzzer_mutation_hierarflow_routines.hpp)
- Update node routines (e.g. `update_fitness`, `update_taint`, `trim_queue` and `update_queue`):
  - [include/fuzzuf/algorithms/vuzzer/vuzzer_update_hierarflow_routines.hpp](/include/fuzzuf/algorithms/vuzzer/vuzzer_update_hierarflow_routines.hpp)
- Other node routines:
  - [include/fuzzuf/algorithms/vuzzer/vuzzer_other_hierarflow_routines.hpp](/include/fuzzuf/algorithms/vuzzer/vuzzer_other_hierarflow_routines.hpp)

## Different part from an original one
In fuzzuf, the implementation of VUzzer is a bit different from the original one. One of the most notable different parts is the lightweight design of the seed queues to reduce the performance overhead of manipulating seeds. A new design of VUzzer uses `OnDiskExecInput` to implement seeds, which can delay I/O operations until it is required.