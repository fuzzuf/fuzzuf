# How to use libFuzzer on fuzzuf

## Usage

```
$ fuzzuf libfuzzer [options]
```

libFuzzer is an AFL like fuzzing algorithm that discover inputs causing target crashes.

The following command executes the target 10000 times.

```
$ fuzzuf libfuzzer -target=/usr/bin/foo -runs=10000
```

This command uses the default input strings as initial inputs.

If initial inputs or dictionaries are available, specify the path by following options.

```
$ fuzzuf libfuzzer -target=/usr/bin/foo -runs=10000 -input=/path/to/inputs -dict=/path/to/dictionary
```

One file in the input directory is loaded as one initial input data.
The dictionary file must have AFL compatible dictionary format.

See also [AFL dictionary format description](https://github.com/google/afl/blob/master/dictionaries/README.dictionaries) and [LLVM's description on AFL dictionary format](https://llvm.org/docs/LibFuzzer.html#dictionaries).


It is also possible to load inputs and dictionaries from multiple directories.

```
$ fuzzuf libfuzzer -target=/usr/bin/foo -runs=10000 -input=/path/to/first_inputs -input=/path/to/second_inputs
```

Default output directory is /tmp/fuzzuf-out\_dir/crash-\<process specific UUID\>. The output directory can be changed by -exact\_artifact\_path=\<path\>

```
$ fuzzuf libfuzzer -target=/usr/bin/foo -runs=10000 -exact\_artifact\_path=/path/to/output
```

## Options

### -target arg

Mandatory option. Path to the target executable.

### -help arg

Print help message (-help=1).

### -input arg 

Provide a dictionary of input keywords; see [Dictionaries](https://llvm.org/docs/LibFuzzer.html#dictionaries).

(Note: this libFuzzer implementation loads input from the directory. Each file in the directory must contain just one input string with 1 or more length.)

### -verbosity arg

Verbosity level, default 1.

### -entropic arg

Use entropic mode, default 0.

### -reduce\_depth arg

Experimental/internal. Reduce depth if mutations lose unique features. Default to 0.

### -shrink arg

Replace values on corpus by shorter input with same coverage, default 0.

### -seed arg

Random seed. If 0, seed is generated. Default to 0.

### -runs arg

Number of individual test runs, -1 (the default) to run indefinitely. If 0, libFuzzer tries to guess a good value based on the corpus and reports it. 

### -max\_len arg

Maximum length of the test input. If 0, libFuzzer tries to guess a good value based on the corpus and reports it. Default to 0.

### -len\_control arg

Try generating small inputs first, then try larger inputs over time.  Specifies the rate at which the length limit is increased (smaller == faster).  If 0, immediately try inputs with size up to max\_len. Default value is 0, if LLVMFuzzerCustomMutator is used.

### -timeout arg

Timeout in seconds (if positive). If one unit runs more than this number of seconds the process will abort. Default to 50 milliseconds.

### -rss\_limit\_mb arg

If non-zero, the fuzzer will exit uponreaching this limit of RSS memory usage. Default to 2 GiB.

### -malloc\_limit\_mb arg

If non-zero, the fuzzer will exit if the target tries to allocate this number of Mb with one  malloc call. If zero (default) same limit as rss\_limit\_mb is applied. Default to 0.

(not implemented yet)

### -timeout\_exitcode arg

When libFuzzer reports a timeout this exit code will be used. Default to 77.

(not implemented yet)

### -error\_exitcode arg

When libFuzzer itself reports a bug this exit code will be used. Default to 77.

(not implemented yet)

### -max\_total\_time arg

If positive, indicates the maximal total time in seconds to run the fuzzer. Default to 0.

(not implemented yet)

### -merge arg 

If 1, the 2-nd, 3-rd, etc corpora will be merged into the 1-st corpus. Only interesting units will be taken. This flag can be used to minimize a corpus. Default to 0.

### -merge\_control\_file arg

Specify a control file used for the merge process. If a merge process gets killed it tries to leave this file in a state suitable for resuming the merge. By default a temporary file will be used.The same file can be used for multistep merge process.

(not implemented yet)

### -minimize\_crash arg

If 1, minimizes the provided crash input. Use with -runs=N or -max\_total\_time=N to limit the number attempts. Use with -exact\_artifact\_path to specify the output. Combine with ASAN\_OPTIONS=dedup\_token\_length=3 (or similar) to ensure that the minimized input triggers the same crash. Default to 0.

(not implemented yet)

### -reload arg

Reload the main corpus every <N> seconds to get new units discovered by other processes. If 0, disabled. Default to 0.

(not implemented yet)

### -jobs arg

Number of jobs to run. If jobs >= 1 we spawn this number of jobs in separate worker processes with stdout/stderr redirected to fuzz-JOB.log. Default to 0.

(not implemented yet)

### -workers arg

Number of simultaneous worker processes to run the jobs. If zero, "min(jobs,NumberOfCpuCores() /2)" is used. Default to 0.

(not implemented yet)

### -dict arg

Experimental. Use the dictionary file. Default to no dictionaries.

### -use\_counters arg

If non-zero, use coverage counters. Default to 0.

### -reduce\_inputs arg

If non-zero, try to reduce the size of inputs while preserving their full feature sets. Default to 0.

### -use\_value\_profile arg

Experimental. If non-zero, use value profile to guide fuzzing. Default to 0.

(not implemented yet)

### -only\_ascii arg

If 1, generate only ASCII (isprint+isspace) inputs. Default to 0.

### -artifact\_prefix arg

Write fuzzing artifacts (crash, timeout, or slow inputs) as $(artifact\_prefix)file. Default is /tmp/fuzzuf-out\_dir/.

(Note: This libFuzzer implementation stores the artifacts in a directory. Each output is stored in different files in the directory.)

### -exact\_artifact\_path arg

Write the single artifact on failure (crash, timeout) as $(exact\_artifact\_path). This overrides -artifact\_prefix and will not use checksum in the file name. Do not use the same path for several parallel processes. 

(Note: This libFuzzer implementation stores the artifacts in a directory. Each output is stored in different files in the directory.)

### -print\_pcs arg

If 1, print out newly covered PCs. Default to 0.

### -print\_final\_stats arg

If 1, print statistics at exit. Default to 0.

### -detect\_leaks arg

If 1, and if LeakSanitizer is enabled try to detect memory leaks during fuzzing (i.e. not only at shut down). Default to 0.

(not implemented yet)

### -close\_fd\_mask arg

If 1, close stdout at startup; if 2, close stderr; if 3, close both. Be careful, this will also close e.g. stderr of asan. Default to 0.

(not implemented yet)

### -seed\_inputs arg

A comma-separated list of input files to use as an additional seed corpus. Alternatively, an "@" followed by the name of a file containing the comma-separated list.

(not implemented yet)

### -keep\_seed arg

If 1, keep seed inputs in the corpus even if they do not produce new coverage. When used with |reduce\_inputs==1|, the seed inputs will never be reduced. This option can be useful when seeds arenot properly formed for the fuzz target but still have useful snippets. Default to 0.

(not implemented yet)

### -cross\_over arg

If 1, cross over inputs. Default to 1.

### -cross\_over\_uniform\_dist arg

Experimental. If 1, use a uniform probability distribution when choosing inputs to cross over with. Some of the inputs in the corpus may never get chosen for mutation depending on the input mutation scheduling policy. With this flag, all inputs, regardless of the input mutation scheduling policy, can be chosen as an input to cross over with. This can be particularly useful with |keep\_seed==1|; all the initial seed inputs, even though they do not increase coverage because they are not properly formed, will still be chosen as an input to cross over with. Default to 0.

### -mutate\_depth arg

Apply this number of consecutive mutations to each input. Default to 5.

### -shuffle arg

Shuffle inputs at startup. Default to 1.

### -prefer\_small arg

If 1, always prefer smaller inputs during the corpus shuffle. Default to 0.

### -check\_input\_sha1 arg

If 1, ignore files in the input directory whose filename does not match the sha1 hash of the file contents. Default to 0.

