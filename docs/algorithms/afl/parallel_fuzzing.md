# Parallel Fuzzing

Some algorithms on fuzzuf suport AFL compatible parallel fuzzing mode.
For more detail on this mode, please refer [original AFL documentation](https://github.com/mirrorer/afl/blob/master/docs/parallel_fuzzing.txt)

## Parallel Fuzzing specific options

On parallel fuzzing capable algorithms, dedicated command line options -M and -S are available.
If one of them are set, fuzzuf expects other fuzzer instances (it may be fuzzuf or may not be) are running in parallel.
Both -M and -S requires instance ID that is a string to identify the instance.
All instances cooperating by parallel fuzzing must have unique instance ID.

If -S is set, the instance is expected to use random mutation. (This functionality is not available yet on fuzzuf)

