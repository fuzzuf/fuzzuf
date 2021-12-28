Why we didn't move to Rust
==

This document explains how and why we abandoned our plan to migrate fuzzuf from C++ to Rust.

## Summary

As the title says, we have abandoned our plans to move to Rust at this time. The reasons are as follows:

 - The concept of HierarFlow, invented in developing fuzzers, is not compatible with Rust, and we believe that HierarFlow is the most reasonable design concept for fuzzuf's goal of becoming a general-purpose framework that can implement any fuzzing algorithm. Therefore, we conclude it is more important for fuzzuf to use HierarFlow than Rust.
 - While the features of Rust and its powerful package manager and build tools are attractive, it is not reasonable to abandon all of the accumulated C\+\+ code for the transition. Also, we cannot ignore the ease of porting existing fuzzing algorithms that C\+\+ has.

## Why we started using C\+\+?

When we started developing fuzzuf, we chose C\+\+ as our development language.

The purpose of fuzzuf is to make it easy to implement and modify any fuzzing algorithm on this framework, and to improve the commonality and reusability of the code base in the entire research field of fuzzing algorithms.

Therefore, among the existing fuzzing algorithms, those of high research importance should be implemented in fuzzuf, which inevitably leads to the selection of a language that is easy to reimplement.

And the majority of such important fuzzing algorithms are implemented in C or C\+\+. Examples include AFL[^afl] and the algorithms proposed based on it (AFLFast[^aflfast], MOpt[^mopt], REDQUEEN[^redqueen], AFLSmart[^aflsmart], AFLGo[^aflgo], IJON[^ijon], FairFuzz[^fairfuzz], AFL\+\+[^aflpp], etc.), and libFuzzer[^libfuzzer] and a set of algorithms proposed based on it (Entropic[^entropic], NEZHA[^nezha]), VUzzer[^vuzzer], honggfuzz[^honggfuzz], etc.

The fact that many fuzzers are written in C or C\+\+ means that fuzzing researchers, the main users of fuzzuf also want to use (or at least can use) C or C\+\+ as their development language. Generally, the language of the framework should be determined based on the language used by the users.

Here, we have chosen C\+\+ instead of C simply because C\+\+ has better language features. Complex algorithms may require complicated data structure with dynamic memory management or elaborate mathematical calculations, which would be difficult to implement in C.

Furthermore, just as AFL-based algorithms are forced to continue to be written in C, which may increase the cost of implementation, algorithms implemented on fuzzuf will continue to be developed in the language of fuzzuf's choice. With this in mind, we have decided to use C\+\+17, which is the most recent version with all the features implemented.

Writing fuzzers in C\+\+(17) means a reduction in portability compared to writing them in C, so perhaps this is not a good decision for commercial applications of fuzzing. However, since fuzzuf's primary interest is in the study of pure fuzzing algorithms, the convenience of the language takes precedence over portability.

## The attraction of Rust

While we opted for C\+\+, it looks like fuzzers written in Rust have slowly started to appear in recent years. In the first place, there is definitely a movement to shift the development language from C or C\+\+ to the safer Rust, not only for fuzzers but for software development in general. We don't think there is any **fuzzing-field-specific** motivation for moving from C or C\+\+ to Rust, but it is natural, considering that developing in Rust reduces not only vulnerabilities but also bugs in fuzzers.

Another advantage of Rust is that it has Cargo's excellent ecosystem, which significantly reduces the effort of building and maintaining your own build environment and build scripts compared to C\+\+.

Furthermore, since fuzzuf uses C\+\+17, it is probably more difficult to utilize it in the embedded field or in layers below the kernel than fuzzers written in pure C. Moving to Rust is attractive as it could solve this problem, as seen in initiatives such as Rust for Linux.

## When we started considering the move to Rust

It is important to note that we started to seriously consider moving to Rust after AFL and libFuzzer were implemented in fuzzuf. The earliest attempt by fuzzuf was to recreate AFL in the first place. As mentioned earlier, porting AFL was a top priority since many of the existing fuzzing algorithms to be implemented are derived from AFL.

In fact, fuzzuf implements AFL in several patterns in order to answer the question, "What design should a framework have in order to be the most versatile to implement arbitrary fuzzing algorithms?". In this process, the concept of HierarFlow was created. After that, HierarFlow was brushed up based on libFuzzer and VUzzer, which were the second implementations.

Since we decided to move to Rust later, we had to consider whether we could implement HierarFlow on Rust's language features and whether HierarFlow could maintain its convenience without violating Rust's language design philosophy.

Of course, if we could find an alternative concept to HierarFlow that was more suitable for Rust and could achieve the goals of fuzzuf, we would adopt it. In some cases we should even consider abandoning Hierarflow and alternative concepts and moving to Rust without them.

Also, the fact that AFL is already implemented would simply mean that AFL would need to be re-implemented in Rust if we were to migrate, and the focus was on whether the migration would be worth the cost.

## Importance of HierarFlow

The biggest barrier to migrating to Rust was definitely whether or not it would adopt HierarFlow. To answer this, we need to think a bit about why fuzzuf introduced HierarFlow in the first place: if HierarFlow is a more important concept than Rust, and has features that are at odds with Rust's language design, then we would have to abort the move to Rust (and indeed, we did). On the other hand, if HierarFlow is a concept that is compatible with Rust or is so unimportant that it can be discarded, then the migration to Rust should be a priority.

Therefore, we will describe here what the designers of HierarFlow were trying to solve with HierarFlow, although there may be some overlap with other documents. In doing so, we will make clear why we needed HierarFlow.

As mentioned earlier, the goal of fuzzuf is to make it easy to implement and modify arbitrary fuzzing algorithms on this framework. In particular, there are many research results published in the world that have obtained better performance by modifying existing fuzzers' codes [^aflfast] [^mopt] [^entropic].

For example, AFL in particular has a huge number of derived algorithms. Many of the derived algorithms are implemented as direct patches to the AFL. Our goal at fuzzuf is to make it easy to reimplement all of these without the need for patches. To achieve this, it was necessary to design fuzzuf in such a way that any changes made to the algorithm can be instantly implemented by reusing as much of the unchanged code as possible and implementing only the changed parts. The concept of HierarFlow was born as a result.

As an example, consider the following pseudo-code:

```
select_seed(algo_state) {
  // Determine which seed to mutate by referring to algo_state.
  mutate(algo_state, algo_state.next_seed_to_mutate())
}

mutate(algo_state, seed) {
  // Perform some mutation by referring to algo_state.
  // For example, in the following, algo_state selects one bit in the input bytes 
  // and bitflips it
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // update algo_state in some way
}
```

This would be a common code pattern in mutation-based fuzzing. We will consider making various changes to it. Note that, as mentioned above, we will not overwrite the code by patching it, but will create a *derived algorithm* so that both the original code and the modified code can be executed.

For example, you may want to change the operation of `mutate`. If you simply write it as a function, it will look like this:

```
select_seed(algo_state) {
  mutate(algo_state, algo_state.next_seed_to_mutate())
}

mutate(algo_state, seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}

select_seed2(algo_state) {
  mutate2(algo_state, algo_state.next_seed_to_mutate())
}

mutate2(algo_state, seed) {
  byteflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // update algo_state in some way
}
```

In this case, due to the restriction that the original code must be maintained, we have to prepare new functions `select_seed2` and `mutate2` for each of the functions `select_seed` and `mutate`. However, as you can see, those functions are mostly copy/paste of the original functions.

This may be partially remedied in languages where functions are first-class objects, or in languages that can handle function pointers and lambda expressions. In that case, the implementation would look like this:

```
select_seed(algo_state) {
  // Determine which seed to mutate by referring to algo_state.
  // At this time, we also pass what kind of mutation is to be performed as a function object
  apply_mutate(algo_state, algo_state.next_seed_to_mutate(), algo_state.next_mutation())
}

apply_mutate(algo_state, seed, mutate_func) {
  mutate_func(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // update algo_state in some way
}
```

However, only a limited number of changes can be handled in this way. For example, in the above snippet, both `bitflip` and `byteflip` take only a single argument, the input position, but there could be mutations that require a dictionary or other special arguments. Alternatively, it is not necessarily the case that we apply only one type of mutation only once. We may apply multiple types of mutations to the same seed, and execute the PUT as many times as we apply them. As long as we have a simple implementation, it is nearly impossible to achieve all these changes with as few differences as possible. This approach to handling the changes is a design that is possible only because we know what the changes are.

Furthermore, the more function objects and callback functions are used to generalize the process in this way, the less readable it becomes, and the more difficult it becomes to see what specific code is being executed, when it is being executed, and where that code is defined.

Alternatively, one might have thought of the following implementation:

```
select_seed(algo_state) {
  // We also pass what kind of mutation is to be performed as a function object
  // We implement execute and update inside that function.
  // In this case, either bitflip or byteflip will be selected.
  mutate <- algo_state.next_mutation()
  mutate(algo_state, algo_state.next_seed_to_mutate())
}

bitflip_mutate(algo_state, seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}

byteflip_mutate(algo_state, seed) {
  byteflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // update algo_state in some way
}
```

This is certainly a more flexible implementation than the previous one, since you can define mutations as you like. However, the fact that all the internals of a mutation function need to be described implies that every time you define a new mutation function, you also need to describe the subsequent processing, such as the execution of PUT or the call to `update_state`. This is a lack of code reusability.

Another problem is that now the only function object that can be customized is `mutate`. As a result, even if you want to make changes only to `update_state`, you will have to change the mutate function. 

Alternatively, it is difficult to customize the seed selection, or to implement an algorithm that does not have a "seed selection -> mutation -> execution -> state update" flow in the first place in this design. In Hybrid Fuzzing [^qsym], for example, it is quite possible that the algorithm does not have the typical flow described above. The existence of algorithms with such special flows also makes it difficult to adopt observer patterns.

Thus, the simple implementation patterns described so far are limited in their expressive power, and are not designed to minimize the size of changes while having enough power to implement all fuzzing algorithms.

This is where HierarFlow comes in, and you can find more information on how to use HierarFlow in other documents. The features of HierarFlow that are relevant to the design issues we have discussed can be summarized as follows: 

 1. HierarFlow establishes a parent-child relationship for routines, so that a child routine can be called from a parent routine at any time and as many times as desired.
 2. The only condition for routine A to have routine B as a child is that the type used by A when it calls children matches the type used by B when it is called.
 3. routines can have any number of child routines that satisfy the condition. If there are multiple child routines, they will be called in order, starting with the first one registered as a child. 
 4. Each routine is represented as a class instance and can hold member variables. Therefore, the routine itself can have state.

In particular, the properties 2. and 4. are important for implementing new features with minimal changes.

Let's see how the pseudo-code in the previous section would look like in HierarFlow. To define the code flow in HierarFlow, we need to define the contents of the routines and the connections between routines. The pseudo-code may look like the following:

```
// Define the routines.

select_seed() {
  // Determine which seed to mutate by referring to algo_state.
  // The reference to algo_state is held by select_seed as a member variable
  // Therefore, it does not appear in the argument
  call_successors(
      algo_state.next_seed_to_mutate()
  )
}

mutate(seed) {
  // The reference to algo_state is held as a member variable
  bitflip(seed, algo_state.next_pos_to_flip())
  call_successors(seed)
}
  
execute(seed) {
  feedback <- execute PUT with seed
  call_successors(seed, feedback)
}

update_state(seed, feedback) {
  // The reference to algo_state is held as a member variable
  ... // update algo_state in some way
}

// Define the code flow (A -> B to make B a child routine of A)

select_seed -> mutate -> execute -> update_state
```

There are two points worth noting here: 
  1. Each routine does not explicitly state which function it will call, but instead uses `call_successors` to state that it will call the child routine. 
  2. Usually, functions need to keep passing `algo_state` as an argument to the function they call, but  The usual function needs to keep passing `algo_state` as an argument to the calling function, but by allowing each routine to have a member variable, it is no longer necessary.

The advantage of 1. is obvious: if you want to change mutate, for example, you can simply prepare a new routine for mutate and connect it to the new routine in the flow definition. Furthermore, as long as the calling types between routines match, it is easy to change the structure of the flow, so it is easy to add or replace mutations, as in the following example:

```
bitflip_mutate(seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  call_successors(seed)
}

byteflip_mutate(seed) {
  // The reference to algo_state is held as a member variable
  bitflip(seed, algo_state.next_pos_to_flip())
  call_successors(seed)
}

select_seed -> [
   bitflip_mutate -> execute -> update_state,
  byteflip_mutate -> execute -> update_state
]
```

Also, if the update function does something different for each mutation, it is enough to define the update routine and redefine the flow appropriately:

```
update_state_for_bitflip(seed, feedback) {
  ... // update algo_state in some way
}

update_state_for_byteflip(seed, feedback) {
  ... // update algo_state in some way
}

select_seed -> [
   bitflip_mutate -> execute -> update_for_bitflip,
  byteflip_mutate -> execute -> update_for_byteflip
]
```

As you can see, designing a flow requires some sense, but using HierarFlow, it is possible to change only the *middle of the process* so that the difference is as small as possible.

The advantage of 2. is that it hides from the routine calls all the arguments other than the ones that can change with each call and should really be passed from one routine to the other. In the above example, `algo_state` is the value to be hidden. While `algo_state` is a variable that manages the overall state of the algorithm, and is certainly needed in most routines, it is unlikely that multiple instances of `algo_state` will be needed and created dynamically. Hence, it is sufficient to be able to always refer to a single instance. That is, the value usually does not change during execution and does not need to be passed as an argument.

However, in the example implemented without HierarFlow, the function `execute` calls the function `update_state`, which requires `algo_state`, so the function `execute` itself needs to take `algo_state` as an argument. (assuming no global variables are used). This is very annoying if you want to change the algorithm partially. The signature of the function is affected by the appearance of values that need to be continually passed as arguments. If `execute` itself didn't require any `algo_state`, then `execute` itself could have been reused to implement a completely different algorithm; however, being forced to accept an unnecessary `algo_state` argument makes the reuse impossible. 

Furthermore, a typical implementation pattern for a partial algorithm change is to define `DerivedAlgoState` to extend the type `AlgoState` of `algo_state`, and then replace some of the `mutate` and `update_state` with other definitions. In this case, in a statically typed language, all functions that take `algo_state` as an argument need to be retyped (copied to another function). Even the function `execute`, which itself does not require `algo_state`, needs to be retyped.

Some of you may think, "Wait, in some languages, if we have a reference or pointer to the base class, we don't need to change it. In other words, if you define something like

```
// DerivedAlgoState is a derived class of AlgoState

select_seed(AlgoState& algo_state) {
  mutate(algo_state, algo_state.next_seed_to_mutate())
}

mutate(AlgoState& algo_state, Seed& seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(AlgoState& algo_state, Seed& seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(AlgoState& algo_state, Seed& seed, Feedback& feedback) {
  ... // update algo_state in some way
}
```

Then, we can realize the update with a partial change like the following:

```
select_seed_derived(DerivedAlgoState& algo_state) {
  mutate_derived(algo_state, algo_state.next_seed_to_mutate())
}

mutate_derived(DerivedAlgoState& algo_state, Seed& seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed) // treated as a reference to AlgoState thereafter
}
```

Sure, that will work, but if you only want to change the `update_state`, you will get downcast:

```
update_state_derived(AlgoState& algo_state, Seed& seed, Feedback& feedback) {
  DerivedAlgoState& derived_algo_state = algo_state; // we are forced to downcast
  ... // update algo_state in some way
}
```

The advantage of HierarFlow is that it addresses these issues. On the other hand, if you are not motivated to *keep all algorithms and make reusability as high as possible*, you can just refactor periodically and you won't need this unique concept.

## Problems in implementing HierarFlow in Rust

There is only one major problem with implementing HierarFlow in Rust: Rust cannot have multiple mutable references. This makes it difficult for each routine to have a reference to a value as a member variable that does not need to be passed as an argument, and thus type signatures can contain such a value.

There are two things to consider here: the first one is *"is it so bad to have values in arguments that do not need to be passed as arguments?"*. I think this is very controversial, but as I have explained, the answer is "we think it is better if they are not included". In fact, in the above example, it would be very tedious to refactor and design if there appear later more different values other than `algo_state` that need to be passed to all called functions.

The other question is whether there is really no way to achieve the goal of "not using values that should not be arguments as arguments". Actually, we have considered two different solutions. However, both of them had disadvantages and could not be adopted. The following is a record of what exactly the solutions are.

#### a. Rc\<RefCell\<T\>\>

If you want to use mutable references in multiple places in Rust, one known option would be to use `Rc<RefCell<T>>`. However, it is simply painful to have to use `borrow` and `borrow_mut` every time you use a value that is not in arguments. Also, the parent routine must always destroy borrowed references before calling `call_successors`. This is because a child routine called via `call_successors` may call `borrow` or `borrow_mut` while the parent routine is calling `borrow_mut`. This rule is very easy to forget and may lead to runtime errors. The advantage of Rust, that it is easy to notice borrowing errors at compile time, is lost.

#### b. Hiding with macros

As a basic premise, if we do not use global variables and do not use `Rc<RefCell<T>>`, mutable references have to be passed via arguments. In other words, in Rust, even when implemented using HierarFlow, the pseudo-code is not as described above, but as follows:

```
// Define the routines.

select_seed(algo_state) {
  call_successors(
      algo_state, algo_state.next_seed_to_mutate()
  )
}

mutate(algo_state, seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  call_successors(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  call_successors(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // update algo_state in some way
}

// Define the code flow (A -> B to make B a child routine of A)

select_seed -> mutate -> execute -> update_state
```

If you implement it this way, you will still have problems such as downcasting when you replace routines in the middle.

However, Rust has a powerful macro that can be used to hide these values. For instance, we can write some proc macros so that the following:

```rust
#![hierarflow_routines(
  share_by_all={ algo_state : AlgoStateTrait }
)]
mod routines {

  struct select_seed {}
  impl HierarFlowCallee for select_seed {
    fn on_call(&mut self) {
      self.call_successors(
        get_algo_state!().next_seed_to_mutate()
      );
    }
  }
  ...
```

will be internally converted into something like the following:

```rust
mod routines {
  struct select_seed {}
  impl HierarFlowCallee for select_seed {
    fn on_call<T>(&mut self, algo_state : &mut T) 
      where T : AlgoStateTrait 
    {
      self.call_successors(
        algo_state.next_seed_to_mutate(),
        algo_state
      );
    }
  }
  ...
}
```

and we can assign the concrete type to the generics `T` only when the routine is used. Thus, we can remove the use of `AlgoState` from the appearance of the code and the actual definition. This way, if you want to use `DerivedAlgoState` instead of `AlgoState`, you can reuse the existing code with little thought.

However, it is clearly not healthy to use macros to hide processing and keep the internal implementation a black box. If the macros made implementation easier without worrying about the internals at all, we would have been a bit more willing to adopt them. In fact, we would not have adopted this solution, as it would not have prevented users from noticing compile or runtime errors caused by these macros, which could have hindered usability.
 
#### :information_source: Room for discussion 

Maybe some readers who have read this far have come up with a better solution for implementing HierarFlow than the one we have discussed so far. Or perhaps some of you have come up with better concepts and practices than HierarFlow in the first place. In the short term, we have made the decision not to move to Rust, but in the medium to long term, we should revisit the idea.

If anyone has any good ideas, please let us know about them on GitHub issues.

## Problems with HierarFlow as implemented in C\+\+.

As a side note, one of the problems with HierarFlow in C\+\+ is that the definitions of nodes and flows tend to get far apart. The more nodes you have, the more disconnected the constructs of the HierarFlowNode instances are from the actual flow definitions that connect the HierarFlowNodes in the code. For example, the definition of HierarFlow in AFL may give you an example. There are also other algorithms where the two definitions are located much farther apart. This makes browsing through the definitions of flows a bit tedious.

The fascinating thing is that in Rust, this can be solved by using macros (which we didn't end up doing).

For example, AFL's HierarFlow would have allowed you to write node constructs and flow definitions at the same time, in the following form:

```rust
  build_hierarflow! [
    SelectSeed {} [ 
      ConsiderSkipMut {},
      RetryCalibrate {},
      TrimCase {},
      CalcScore {},
      ApplyDetMuts apply_det_muts {} [
        BitFlip1 {} -> ExecutePUT {} [
                         NormalUpdate {},
                         ConstructAutoDict {}
                       ],
        BitFlipOther {} -> ExecutePUT {} -> NormalUpdate {},
        ...
      ],
      ApplyRandMuts apply_rand_muts {} [
        Havoc { stage_max_multiplier: 256 } -> ExecutePUT {} ->  NormalUpdate {},
        Splicing { stage_max_multiplier: 32 } -> ExecutePUT {} ->  NormalUpdate {},
      ],
      AbandonEntry abandon_entry {},
      
      maybe_goto! [
          apply_det_muts -> abandon_entry,
          apply_rand_muts -> abandon_entry
      ]
    ]
  ]
```

In the future, we may change the notation and design of HierarFlow even in C\+\+ to allow constructing nodes and defining flows at the same time, but there are some issues with the current specification that make it difficult at this point.

## References

[^afl]: Michal Zalewski. "american fuzzy lop" https://lcamtuf.coredump.cx/afl/

[^libfuzzer]:  "libFuzzer – a library for coverage-guided fuzz testing." https://llvm.org/docs/LibFuzzer.html

[^aflfast]:  Marcel Böhme, Van-Thuan Pham, and Abhik Roychoudhury. 2016. Coverage-based Greybox Fuzzing as Markov Chain. In Proceedings of the 23rd ACM Conference on Computer and Communications Security (CCS’16).

[^vuzzer]: Sanjay Rawat, Vivek Jain, Ashish Kumar, Lucian Cojocar, Cristiano Giuffrida, and Herbert Bos. 2017. VUzzer: Application-aware Evolutionary Fuzzing. In the Network and Distribution System Security (NDSS’17).

[^mopt]: Chenyang Lyu, Shouling Ji, Chao Zhang, Yuwei Li, Wei-Han Lee, Yu Song, and Raheem Beyah. 2019. MOpt: Optimized Mutation Scheduling for Fuzzers. In Proceedings of the 28th USENIX Security Symposium (Security'19).

[^nezha]: Theofilos Petsios, Adrian Tang, Salvatore Stolfo, Angelos D. Keromytis, and Suman Jana. 2017. NEZHA: Efficient Domain-Independent Differential Testing. In Proceedings of the 38th IEEE Symposium on Security and Privacy (S&P'17).

[^qsym]: Insu Yun, Sangho Lee, Meng Xu, Yeongjin Jang, and Taesoo Kim. 2018. QSYM : A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing. In Proceedings of the 27th USENIX Security Symposium (Security'18).

[^aflgo]: Marcel Böhme, Van-Thuan Pham, Manh-Dung Nguyen, and Abhik Roychoudhury. Directed Greybox Fuzzing. In Proceedings of the 24th ACM Conference on Computer and Communications Security (CCS'17).

[^ijon]: Cornelius Aschermann, Sergej Schumilo, Ali Abbasi, and Thorsten Holz. 2020. IJON: Exploring Deep State Spaces via Fuzzing. In Proceedings of the 41st IEEE Symposium on Security and Privacy (S&P'20).

[^aflpp]: Andrea Fioraldi, Dominik Maier, Heiko Eißfeldt, and Marc Heuse. 2020. AFL++: Combining Incremental Steps of Fuzzing Research. In Proceedings of the 14th USENIX Workshop on Offensive Technologies (WOOT'20).

[^redqueen]: Cornelius Aschermann, Sergej Schumilo, Tim Blazytko, Robert Gawlik, and Thorsten Holz. 2019. REDQUEEN: Fuzzing with Input-to-State Correspondence. In the Network and Distribution System Security (NDSS'19).

[^aflsmart]: Van-Thuan Pham, Marcel Böhme, Andrew E. Santosa, Alexandru Răzvan Căciulescu, Abhik Roychoudhury. 2019. Smart Greybox Fuzzing. In IEEE Transactions on Software Engineering (TSE'1).

[^entropic]: Marcel Böhme, Valentin J.M. Manès, and Sang K. Cha. 2020. Boosting Fuzzer Efficiency: An Information Theoretic Perspective. In Proceedings of the 28th ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering (ESEC/FSE'20).

[^fairfuzz]: Caroline Lemieux and Koushik Sen. 2018. FairFuzz: A Targeted Mutation Strategy for Increasing Greybox Fuzz Testing Coverage. In Proceedings of the 33rd ACM/IEEE International Conference on Automated Software Engineering (ASE'18).

[^honggfuzz]: "honggfuzz" https://honggfuzz.dev/
