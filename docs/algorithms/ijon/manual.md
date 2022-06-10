# How to use IJON on fuzzuf

## Usage

```
$ fuzzuf ijon [options]
```

IJON is an annotation mechanism to guide AFL like fuzzers.

Therefore, available options are same as AFL except forkserver is the only valid value for --executor and Frida mode is not available.

PUT must be compiled using fuzzuf-ijon-cc that is provided by separated fuzzuf-cc repository.
PUT compiled by original IJON implementation is not compatible with fuzzuf.

Basic usage is shown below.

```
$ fuzzuf ijon --in_dir <INDIR> --out_dir <OUTDIR> --executor forkserver <PUT>
```

INDIR is a directory containing initial input values. Each files in the directory is considered as one input value.

OUTDIR is a directory to output intermediate state and results.

PUT is a path to executable to run.

