# fuzzuf To-Dos

This document is our to-do list that contains things we would like to do in the future. The list includes not only things that need fixing, but also new features that we are planning to add. Therefore, this document shows the future prospect of fuzzuf.

The listed to-dos are divided into two types: to-dos that require careful consideration and ones that don't. 
  - The former ones would take some time for us to handle because dealing with it would cause a big change on the code base or because we must elaborate designs before starting implmentation. Therefore, **even if you would like to contribute to these to-dos and you suddenly send PRs for them without notice and agreement, unfortunately it's very likely that we would be unable to accept your PRs**. Alternatively, it would be greatly appreciated if you would join discussions by creating issues. After reaching a conclusion, you and we can start implementation works.
  - On the other hand, the latter ones are more trivial to do and can be handled if we have time. Sending PRs for them is very helpful anytime. 

## To-Dos that require careful consideration

### Unify the designs of RNG (random number generators) and probability distributions

Considering that most fuzzing algorithms behave stochastically by nature, reproducibility matters a lot. To reproduce the results of prior researches or bugs found during some experiments, we should be able to get a complete control over sources of randomness. As you may know, this demand can be seen also in the field of data science, and many languages and libraries in that field (such as R, Python, numpy and tensorflow, etc.) have the features to that end. As a framework, fuzzuf also should be able to configurate them. In other words, fuzzuf must have its own RNGs and must discourage the users against using other original RNGs that cannot be controlled by fuzzuf. We expect such changes would work also as a kind of dependency injection to make fuzzuf more robust.

Some people may want to use their own implementation of RNGs that are not based on fuzzuf, but such acts are not hygiene. In almost all cases, fuzzing algorithms should not depend on a particular RNG algorithm, nor include it as a part of the algorithm, nor *cherry-pick* it to hope accidental performance improvements (of course, we don't mean algorithms should work well even if the used RNG is pathologically biased!). On the contrary, all the fuzzing algorithms ideally should use the same RNG algorithm for fair comparison. 

At this moment we are thinking about defining the RNG so that the following properties are fulfilled:
  - It must satisfy [RandomNumberEngine](https://en.cppreference.com/w/cpp/named_req/RandomNumberEngine).
      - Especially, it should return a number in the closed interval [0, 2 ^ 64 - 1] uniformly randomly.
      - Maybe we need to define more variants U([0, 2 ^ 32 -1]), U([a, b]) in case of performance degradation or for ease of use.
  - It must work fast enough, and must not be biased too much.
      - It is debatable to what extent it is allowed to be biased. Are LCGs admissible? How about modulo bias?
      - Currently the candidates are [XORSHIFT-ADD](http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/XSADD/index.html) or [PCG](https://www.pcg-random.org/index.html). 
        - c.f. https://arxiv.org/abs/1810.05313

Moreover, it would be preferable if fuzzuf has some utilities related to RNGs and distributions. 
For example, the followings can be considered:
  - DebugRng: the (non-)random number generator that can be used for tests and debugs. For example, DebugRng({1, 2, 3}) will repeatedly returns 1, 2, 3, 1, 2, ... instead of random numbers. Without this RNG, writing tests may be frustrating sometimes.
    - However, we are not sure in what way this should be provided because it's ridiculous to be forced to define something with `template<class Rng>` just for switching DebugRng and ActualRng in tests and the others.
  - DebugDistribution: returns the specified sequence of numbers similarly to DebugRng.

The following pseudo code shows the currently considered design:

```cpp
fuzzuf::rand::SetGlobalSeed(1234);     // make all the seeds fixed globally
auto rng1 = fuzzuf::rand::CreateXSAdd(); // create a XORSHIFT-ADD RNG seeded with f(1234, 0) (f is TBD)
std::uniform_int_distribution<> dist1(0, 3);
for (int i=0; i<100; i++) {
    std::cout << dist1(rng1) << std::endl; // fuzzuf's RNGs should be compatible with std
}
auto rng2 = fuzzuf::rand::CreateXSAdd(); // create RNG seeded with f(1234, 1)
fuzzuf::rand::WalkerDiscreteDistribution<> dist2({10, 20, 30}); // has the same interface as std::discrete_distribution, but is implemented with Walker's alias method
for (int i=0; i<100; i++) {
    std::cout << dist2(rng2) << std::endl;
}
auto rng3 = fuzzuf::rand::CreateXSAdd(5678); // create a XORSHIFT-ADD RNG seeded directly with 5678. This constructor will be used mostly for debug purposes.
...
```

After we define and implement the RNG, we should replace with it all the usages of other RNGs and distributions, such as `rand()` or `fd = fopen("dev/null", "r"); fread(fd, sizeof(u8), 4, buf);`. This would take some time.

### Implement fuzzuf-cc, our own instrumentation tool 

As you may notice, we don't have any own instrumentation tool yet. We recommend you to use AFL\+\+'s afl-cc (hereinafter referred to as afl\+\+-cc) for the time being. Technically, we wrote some internal instrumentation tool and have been using it. However, we would like to abandon it because the tool is no more than a subset of afl\+\+-cc. Also, it would be more useful if fuzzuf is compatible with PUTs built with afl\+\+-cc. 

However, some algorithms require special kinds of instrumentation that are not implemented in afl\+\+-cc. For example, afl\+\+-cc doesn't support basic block coverage, which is required in VUzzer (To be precise, it doesn't call for a compile-time instrumentation tool because it actually uses pintool. But it's just a possible example). Another example is SpeedNeuzz that uses the modfied version of AFL's edge coverage. We don't think afl\+\+-cc has to be equipped with those instrumentations because usually they perform worse than afl\+\+-cc's refined edge coverage and because AFL\+\+ doesn't need them in the first place. This means fuzzuf must supply *fuzzuf-cc*, its own instrumentation tool eventually because our goal is to provide a general framework, which is different from AFL\+\+.

We are planning to write fuzzuf-cc in Python 3, whereas AFL and AFL\+\+ wrote their instrumentation tool in C. This is because we realized writing a wrapper of compilers in C makes it not extensible. As described above, we made an internal instrumentation tool by patching afl-cc. Then, we felt that the tool would get messier if we add more features and more options to it, and that we wouldn't want to maintain it. We think the maintenance would be easier if we write it in Python. We will write just a wrapper of compilers and plugins for them, not a compiler itself. Of course, the plugins, such as fuzzuf-llvm-rt.o (equivalent of afl-llvm-rt.o), LLVM Pass, or GCC plugins still must be written in C and C\+\+. Nevertheless, loading the plugins in Python will definitely makes the code concise, which enables us to add and merge a new instrumentation easily.

We are still deciding the followings:
  - Whether we keep fuzzuf compatible with afl(\+\+)-cc
    - Probably we do so
  - How fuzzuf-cc provides features that are not in AFL, such as basic block coverage
    - Should coverages are recorded in the shared memory specified by `__AFL_SHM_ID` even if basic block coverage is enabled?
      - In that case, don't we have to distinguish which type of coverage is used in a given PUT?
    - Or should we insert something different like `__FUZZUF_SHM_ID`?
  - Whether we should make it possible for multiple kinds of instrumentation to be enabled simultaneously
    - One of the benefits of doing so is that we can use exactly the same PUT for different fuzzers
    - However, for fair comparison, it's inevitable to have another PUT to measure coverage as fuzzbench does because the scale of coverage is different between different kinds of coverage
  - Whether we should insert some section in binaries to distinguish which instrumentation is enabled

This to-do is very important to complete libFuzzer because it use some metrics like stack depth to determine the value of a seed, and those metrics are not yet implemented.

Also, we need to replace all the tests that use raw binaries in the repo after this to-do is resolved. That is definitely unsound.

### Support multiple types of executors in the fuzzers

At present, the fuzzers implemented in fuzzuf employ one fixed executor and don't support switching executors. However, there are many fuzzers that can work with different sorts of executor. For example, the original AFL has QEMU mode, which enables AFL to work without compile-time instrumentation. Another example might be VUzzer. VUzzer originally uses pintool to obtain basic block coverage, but it doesn't matter if we use QEMU or compile-time instrumentation instead as long as basic block coverage is correctly extracted. Thus, we should design executors and their usage so that algorithms can use them interchangeably if possible.

Here comes OOP. We first need to think how to achieve polymorphism. One ordinary way would be to provide a base class like `BasicBlockExecutor` and its method `BasicBlockExecutor::GetBasicBlockCov()`. Alternatively, template classes may be usable. Another interesting way is to rely on HierarFlow. If we carefully build a flow, we can swap executors by just swapping a node that represents the execution of PUT.

We should work on this to-do after `QemuExecutor` and `PintoolExecutor` are completely ready.

### "Daemonize" and enhance the fuzzuf CLI

This is still just an idea, but it would be nice if fuzzuf has an interface similar to docker and fuzzer instances can be managed like containers. That probably makes the profiling of instances easier. Perhaps even clustering servers is possible like docker swarm.

We can improve the fuzzuf CLI otherwise. For instance, we can make fuzzuf able to receive fuzzer options via other formats than command line arguments, like JSON and YAML. Besides, because we can register subcommands to the `fuzzuf` command, it's possible to have some utilities like `fuzzuf plot` or `fuzzuf minimize-testcase`.

### Update `HierarFlowRoutine::CallSuccessors`

As a comment in `HierarFlowRoutine::CallSuccessors` says, `HierarFlowCallee<I>::operator()` doesn't need to return `NullableRef<HierarFlowCallee<I>>` now. Formerly, HierarFlowNode has been expressed by linked lists, which made us use NullableRef (equivalent of raw pointer) to efficiently describe which node should be executed next. Now that HierarFlowNode is implemented with std::vector, `HierarFlowCallee<I>::operator()` can return integers(indices) instead of pointers. Although there is no worry about applying this change, the change is just too big to be suddenly made without notice to the others. Also, we'll have to update some documents.

### Implement more fuzzing algorithms

The following algorithms are currently planned to be implemented:  

- MOpt [^mopt]
- Eclipser [^eclipser]
- QSYM [^qsym]

About some algorithms, it is difficult to determine what is considered a *complete* implementation. For example, Eclipser is designed differently in v1.0 and v2.0, and we have to discuss whether to implement one or the other (or both). Such algorithms require some discussions.

Among these, the implementation of MOpt is in progress.

### Implement more types of Executor

The following executors will be implemented in the future:

- WindowsExecutor (will be implemented with reference to WinAFL [^winafl], WINNIE [^winnie], etc.)
- AndroidExecutor
- Other Executor using dynamic instrumentation tools such as Frida and DynamoRIO

### Take various benchmarks

We need to benchmark our implementation to know how fast it really is. In addition, the more benchmarks we have, the more likely we are to notice degrades and bugs. Maybe the results of benchmarking will help us come up with new algorithm ideas. We would like to talk about what kind of benchmarks would be nice to have.

## To-Dos that don't require careful consideration

### Add the *virtual* fork server for the non-fork-server mode of `NativeLinuxExecutor`

`NativeLinuxExecutor` has two modes: fork-server mode and non-fork-server mode. These modes are implemented by reference to AFL. However, that implementation has some issues. Its worst drawback is that it heavily uses signals and per-process timers. This means it can't have multiple fuzzer instances in one process (though we are not sure if someone has such purposes in practice). Also, it prevents us from consolidating signal handlers because AFL requires another signal handler for its private use. These issues can be resolved by preparing *virtual* fork server, which follows the same protocol as the fork server inside PUTs compatible with fork-server mode, and which internally executes a specified PUT with fork() and exec() once it receives the request to do so. Actually, AFL\+\+ has this feature.

### Implement persistent mode in `NativeLinuxExecutor`

We should implement this: https://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html
With this mode, the performance of fuzzuf's libFuzzer would be comparable to that of the original libFuzzer.

### Remove raw pointers/buffers from `Mutator`

It's too bad `Mutator` has some raw pointers as its members, such as `u8 *Mutator::outbuf` and `u8 *Mutator::tmpbuf`. These members can be smart pointers or `std::vector`. We just want to replace them.

### Implement resume mode and parallel fuzzing in AFL

They are just unimplemented.

### Implement SIGUSR1 Handling on AFL

This feature is just unimplemented.

### Remove careless templates from AFL

In the implmentation of AFL, we use a lot of `template` to allow users to define the derived classes of `AFLTestcase` and `AFLState`. But this is just cutting corners. Let us explain what we've done with an example. Let's say, we want to define a function that takes a reference of some struct as an argument. The struct has a member named "x". The function would look like the following:

```
void SomeFunc(const SomeStruct& stru) {
  std::cout << stru.x << std::endl;
}
```

Next, we would like to generalize this function so that it can accept similar struct types. Specificallt, we should be able to pass to the function the instances of other structs that have the member "x". Obviously, we can do that in the following way:

```
template<class Struct>
void SomeFunc(const Struct& stru) {
  std::cout << stru.x << std::endl;
}
```

But, another possible solution would be to define the virtual member function `SomeStruct::GetX()`, and to make other structs derive it. Like this way:

```
// Define SomeStruct::GetX() in advance
void SomeFunc(const SomeStruct& stru) {
  std::cout << stru.GetX() << std::endl;
}
```

We should rewrite the classes of AFL in the same way eventually.

### Add CODING\_RULE.md and refactor the code in accordance with CODING\_RULE.md

In the past, we didn't have no explicit coding rules. Nevertheless, we have continued developping fuzzuf simultaneously and almost independently of each other. As a result, the code base doesn't look well-organized. This would make the contributors and users confusing, so we must fix it. We have already almost finished creating CODING\_RULE.md internally. We will release it after review and formatting is complete. After Especially, because we started implementing libFuzzer at a very early stage, the large part of the implementation of libFuzzer doesn't conform to that rules. We will resolve this issue gradually simply because they are too large to fix immediately.

[^mopt]: Chenyang Lyu, Shouling Ji, Chao Zhang, Yuwei Li, Wei-Han Lee, Yu Song, and Raheem Beyah. 2019. MOpt: Optimized Mutation Scheduling for Fuzzers. In Proceedings of the 28th USENIX Security Symposium (Security'19).
[^eclipser]: Jaeseung Choi, Joonun Jang, Choongwoo Han, and Sang K. Cha. 2019. Grey-box Concolic Testing on Binary Code. In Proceedings of the 41st ACM/IEEE International Conference on Software Engineering (ICSE'19).
[^qsym]: Insu Yun, Sangho Lee, Meng Xu, Yeongjin Jang, and Taesoo Kim. 2018. QSYM : A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing. In Proceedings of the 27th USENIX Security Symposium (Security'18).
[^die]: Soyeon Park, Wen Xu, Insu Yun, Daehee Jang, and Taesoo Kim. 2020. Fuzzing JavaScript Engines with Aspect-preserving Mutation. In Proceedings of the 41st IEEE Symposium on Security and Privacy (S&P’20).
[^winafl]: Google Project Zero. "WinAFL" https://github.com/googleprojectzero/winafl
[^winnie]: Jinho Jung, Stephen Tong, Hong Hu, Jungwon Lim, Yonghwi Jin, and Taesoo Kim. 2021. WINNIE: Fuzzing Windows Applications with Harness Synthesis and Fast Cloning. In the Network and Distribution System Security (NDSS'21).


