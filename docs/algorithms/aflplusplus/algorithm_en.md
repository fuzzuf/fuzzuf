# AFLplusplus (AFL++)

## Description

[https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

AFLplusplus[^woot20] is a superior fork to Google's (Michał Zalewski's) AFL, originally began as a collection of patches applicable to AFL v2.52b, which had become inactive at then.

After Zalewski released AFL v2.52b in 2017 and stopped updating, lots of community-provided patches have been published for fixes and enhancements (e.g. llvm-mode fixes and qemu-mode optimization). However, some of them conflicted when applied together since they are based on the same origin, and sometimes tried to overwrite the same line. Marc Heuse started merging them into one single repository as AFLplusplus in 2019 with Marcel Böhme's AFLFast patch[^group-uqRFf7rmCQAJ] [^group-jSNsWNmPCAAJ].

As it got updated, Heuse and developer team did not only enhanced existing features, but also adopted new ones including multi-architecture support, more ways to perform binary-only fuzzing, new mutators and instrumentations proposed in academic papers, and so on.

fuzzuf currently adopts fuzzer-side enhancements in AFLplusplus only. That is, compiler-side enhancements (e.g. NeverZero) are not included.

## List of enhanced features

### FAST3

Originally provided as a patch to improve scheduling (a way to compute seed's score) for AFLplusplus by Marcel Böhme (an author of AFLFast) in [AFLplusplus/AFLplusplus@e87eca7f](https://github.com/AFLplusplus/AFLplusplus/commit/e87eca7f) (later improved by AFLplusplus developers).

Before the PR was made, there were some experiments done on fuzzbench to compare the performance among several parameter tunings. It seems the adopted one is a something between schedulings called fast3 and fast4.

Moreover, the patch changes `n_fuzz` from u32 in `struct queue_entry` (which is equivalent to `Testcase` in fuzzuf) to an array of u32 in `struct afl_state` (equivalent to `AFLState` in fuzzuf), and `queue_entry` now holds `n_fuzz_entry`, which is an index number for that array.  
This is to resolve the performance bottleneck where AFL++ tried to match checksum in a while-loop naively.

fuzzuf's implementation fixed two possible bugs:

- div by zero in LIN and QUAD schedulings
- division done in `u32`, not in `double`

### more_havoc

They also added several new mutations to havoc with their probability to be chosen. It is unclear what that probability is based on.

The first change occurred in [AFLplusplus/AFLplusplus@70bf4b4a](https://github.com/AFLplusplus/AFLplusplus/commit/70bf4b4a) as `havoc2` (a name of the merged branch)  to change the uniform probability of mutations to make them have their own values.

Nextly, new mutations came in at [AFLplusplus/AFLplusplus@b8e61da8](https://github.com/AFLplusplus/AFLplusplus/commit/b8e61da8) as `more_havoc`. This PR reflects those probabilities with Walker's alias distribution.

### Weighted random seed selection

Although the original AFL selects its seeds sequentially, it was pointed out that choosing them randomly produces a better fuzzing result.

AFL++ adopted a random seed selection with Walker's alias method at [AFLplusplus/AFLplusplus@6a397d61](https://github.com/AFLplusplus/AFLplusplus/commit/6a397d61). At this point, weights (values) used to create the alias table are based on the conventional `calculate_score()` function.

Thereafter, a patch by Marcel Böhme ([AFLplusplus/AFLplusplus@06ec5ab3](https://github.com/AFLplusplus/AFLplusplus/commit/06ec5ab3)) changed AFL++ to use the new `compute_weight` function to create it. The purpose of this patch was:
> This commit extends the weight-based sampling by assigning weights based on how often the seed's path is exercised, the number of branches it covers, and the time it takes to execute.

## CLI usage

Just like fuzzuf's AFL or AFLFast, you can use AFL-like syntax on CLI on fuzzuf-AFLplusplus. So we're not going explain the common options here again.

To start a fuzzing from CLI, execute the following in your shell:

```shell
cd /path/to/fuzzuf
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_ALGORITHMS=aflplusplus # add other algos if you want
cmake --build build -j $(nproc)
./build/fuzzuf aflplusplus -i /path/to/input_dir/ -- /path/to/PUT @@
```

AFLplusplus's local options currently implemented are follows:

- `-D [ --det ]`: Enable deterministic stages (AFLplusplus skips them by default to gain its performance)
- `-p [ --schedule ]` arg (=fast): Select power schedule to use (default to FAST). You must specify in a lowercase string which is one of **fast, coe, explore, lin, quad, exploit**.  

For example, to enable deterministic mutation stages and choose the `COE` seed scheduling, do the following:

```shell
./build/fuzzuf aflplusplus -i /path/to/input_dir/ -D -p coe -- /path/to/PUT @@
```

[^woot20]: [AFL++: Combining Incremental Steps of Fuzzing Research](https://aflplus.plus/papers/aflpp-woot2020.pdf)

[^group-uqRFf7rmCQAJ]: [Fix for QEMU install memfd issues on glibc 2.27](https://groups.google.com/g/afl-users/c/9WFfQqNS6qk/m/uqRFf7rmCQAJ)

[^group-jSNsWNmPCAAJ]: [afl++ is now available](https://groups.google.com/g/afl-users/c/dvSou7uT2Qs/m/jSNsWNmPCAAJ)
