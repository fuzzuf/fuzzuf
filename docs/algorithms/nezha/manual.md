# How to use Nezha on fuzzuf

## Usage

```
$ fuzzuf nezha [options]
```

Nezha is a differential fuzzer that executes multiple targets with the same input, and finds input that causes a different result for each target.

Since, Nezha compares two targets, the option must specify at least two targets.

The following command runs each targets 10000 times.

```
$ fuzzuf nezha -target=/path/to/first_executable -target=/path/to/second_executable -runs=10000
```

This command uses the default input strings as initial inputs.

If initial inputs or dictionaries are available, specify the path by following options.

```
$ fuzzuf nezha -target=/path/to/first_executable -target=/path/to/second_executable -runs=10000 -input=/path/to/inputs -dict=/path/to/dictionary
```

One file in the input directory is loaded as one initial input data.
The dictionary file must have AFL compatible dictionary format.

See also [AFL dictionary format description](https://github.com/google/afl/blob/master/dictionaries/README.dictionaries) and [LLVM's description on AFL dictionary format](https://llvm.org/docs/LibFuzzer.html#dictionaries).

It is also possible to load inputs and dictionaries from multiple directories.

```
$ fuzzuf nezha -target=/path/to/first_executable -target=/path/to/second_executable -runs=10000 -input=/path/to/first_inputs -input=/path/to/second_inputs
```

Default output directory is /tmp/fuzzuf-out\_dir/crash-\<process specific UUID\>. The output directory can be changed by -exact\_artifact\_path=\<path\>

```
$ fuzzuf nezha -target=/path/to/first_executable -target=/path/to/second_executable -runs=10000 -exact\_artifact\_path=/path/to/output
```

## Options

All options from [libFuzzer](/docs/algorithms/libfuzzer/manual.md) are available in Nezha.

Additionaly, the following option is provided.

### -use\_output arg

If 0, the exit status difference of each target are treated as differences of targets. Otherwise, the standard output difference of each target is treated as the difference of the targets. Default to 0.

