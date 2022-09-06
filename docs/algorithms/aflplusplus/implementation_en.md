# AFLplusplus implementation on fuzzuf

The same as fuzzuf's AFLfast, it templates or overrides components from [AFL](/docs/algorithms/afl/algorithm_en.md) as follows:

- `ApplyDetMutsTemplate<AFLplusplusState>::operator()`
- `AbandonEntryTemplate<AFLplusplusState>::operator()`
- `SelectSeedTemplate<AFLplusplusState>::operator()`
- `HavocTemplate<AFLplusplusState>::operator()`
- `AFLplusplusState::UpdateBitmapScoreWithRawTrace`
- `AFLplusplusState::SaveIfInteresting`
- `AFLplusplusState::DoCalcScore`
- `AFLplusplusState::ShowStats`

There are no additional HierarFlow routines.

There are some class member functions and variables added for it.

## Schedulings

As AFLplusplus is partially based on AFLFast, it uses the same enum `fuzzuf::algorithm::aflfast::option::Schedule` for a scheduling selection.

### Experimental schedulings

There are two additional schedulings available in the original AFLplusplus, `MMOPT` and `RARE`. As they are (still?) experimental, fuzzuf omitted their implementations.

## Havoc stage

### Mutations added

There are three new mutations added:

- `AFLPLUSPLUS_ADDBYTE`
- `AFLPLUSPLUS_SUBBYTE`
- `AFLPLUSPLUS_SWITCH_BYTES`

### Stage name

Although the original AFLplusplus keeps its stage name as `havoc`, fuzzuf explicitly sets the name as `more_havoc` to distinguish the changes and ensure if the fuzzer is actually executing such stages.
