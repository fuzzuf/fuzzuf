# American Fuzzy Lop

## What is AFL?

https://github.com/google/AFL

AFL (American Fuzzy Lop) is a coverage-guided fuzzer developed by Michał Zalewski in 2013. AFL is a family of mutation-based fuzzers that choose one of the seeds saved in the queue, and tries to discover previously unknown execution paths with seed mutations. In other words, AFL applies genetic algorithms against seeds.

It is also worth mentioning that AFL has become the basis of many other fuzzing algorithms. There are various fuzzing researches that have successfully achieved performance gains [^1] [^2] [^3], extensions for applicable PUTs and environments [^4] [^5], and conversions into an unusual/unique usage [^6] [^7], with partially modifying the original implementation of AFL.

## How to use fuzzuf's AFL CLI

Once you have installed `fuzzuf`, you can start AFL fuzzer as follows:

```shell
$ fuzzuf afl --in_dir=path/to/initial/seeds -- path/to/PUT @@
```

Options available are listed below:

- Global options (available for all fuzzers on `fuzzuf`)
    - `--out_dir=path/to/output/directory`
        - Specifies a path to the directory, where all the outputs from fuzzers go, such as crash seeds. The default path `/tmp/fuzzuf-out_dir` is used if not specified.
    - `--exec_timelimit_ms=1234`
        - Specifies a time limit per PUT execution in milliseconds. The default time limit is 1 second (i.e. 1000 ms).
    - `--exec_memlimit=1234`
        - Specifies the amount of memory available per PUT execution in megabytes. The default memory limit is 25 MB in 64-bit environment, and 50 MB in 32-bit environment.
    - `--log_file=path/to/log/file`
        - Specifies a path to the file, where log outputs (and debug-log outputs if built with debug mode) go. Logs are printed to stdout if a path is not specified.

- Local options (only available for AFL)
    - `--dict_file=path/to/dict/file`
        - Specifies a path to the file, loaded as an additional dictionary.

## Algorithm Overview

TODO: Add AFL algorithm overview

## References

[^1]: Marcel Böhme, Van-Thuan Pham, and Abhik Roychoudhury. 2016. Coverage-based Greybox Fuzzing as Markov Chain. In Proceedings of the 23rd ACM Conference on Computer and Communications Security (CCS’16).
[^2]: Chenyang Lyu, Shouling Ji, Chao Zhang, Yuwei Li, Wei-Han Lee, Yu Song, and Raheem Beyah. 2019. MOpt: Optimized Mutation Scheduling for Fuzzers. In Proceedings of the 28th USENIX Security Symposium (Security'19).
[^3]: Andrea Fioraldi, Dominik Maier, Heiko Eißfeldt, and Marc Heuse. 2020. AFL++: Combining Incremental Steps of Fuzzing Research. In Proceedings of the 14th USENIX Workshop on Offensive Technologies (WOOT'20).
[^4]: Sergej Schumilo, Cornelius Aschermann, Robert Gawlik, Sebastian Schinzel, and Thorsten Holz. 2017. kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels. In Proceedings of the 26th USENIX Security Symposium (Security'17).
[^5]: Google Project Zero. "WinAFL" https://github.com/googleprojectzero/winafl
[^6]: Cornelius Aschermann, Sergej Schumilo, Ali Abbasi, and Thorsten Holz. 2020. IJON: Exploring Deep State Spaces via Fuzzing. In Proceedings of the 41st IEEE Symposium on Security and Privacy (S&P'20).
[^7]: Marcel Böhme, Van-Thuan Pham, Manh-Dung Nguyen, and Abhik Roychoudhury. Directed Greybox Fuzzing. In Proceedings of the 24th ACM Conference on Computer and Communications Security (CCS'17).

