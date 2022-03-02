# IJON implementation in fuzzuf

## Reference IJON Implementation

- Version: 2.51b-ijon
- Commit: https://github.com/RUB-SysSec/ijon/commit/56ebfe34709dd93f5da7871624ce6eadacc3ae4c

## Differences from the original implementation

Unless there are unintended discrepancies due to bugs, the original implementation has been completely reproduced and there are no differences between it and ours.
However, the functions of the original AFL, which are not implemented in fuzzuf AFL, of course cannot be used in IJON.

## Important To-Do: Implementing Annotations

It should be noted that annotations, which must be a major component of IJON, are not implemented in fuzzuf at present.
This is due to the fact that fuzzuf does not have its own instrumentation tool yet, and therefore we will start implementing it as soon as the instrumentation tool is ready.
For other To-Dos, please check [TODO.md](https://github.com/fuzzuf/fuzzuf/blob/master/TODO.md).

## HierarFlow routines that have been added

- SelectSeed: selects a seed from the IJON seed queue.
- PrintAflIsSelected: prints that AFL is selected when AFL's code flow is selected with 20% probability.
- MaxHavoc: starts the havoc stage when IJON's code flow is selected with 80% probability.
- UpdateMax: updates the IJON seed queue.
