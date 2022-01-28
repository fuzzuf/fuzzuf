# AFLFast Implementation on fuzzuf

The fuzzuf AFLFast implementation reuses the [AFL implementation](/docs/algorithms/afl/algorithm_en.md) by templating or overriding the following methods:
- `ApplyDetMutsTemplate<AFLFastState>::operator()`
- `AbandonEntryTemplate<AFLFastState>::operator()`
- `AFLFastState::AddToQueue`
- `AFLFastState::UpdateBitmapScoreWithRawTrace`
- `AFLFastState::SaveIfInteresting`
- `AFLFastState::DoCalcScore`
- `AFLFastState::ShowStats`

## Options

The power schedules described in the [AFLFast algorithm document](/docs/algorithms/aflfast/algorithm_en.md) are available. `FAST` is used by default.

### Use from C++ code

To use the fuzzuf AFLFast from C++ code, create the `AFLFastSetting::AFLFastSetting` instance with `schedule` argument specified. Refer to [include/fuzzuf/algorithms/aflfast/aflfast_option.hpp](/include/fuzzuf/algorithms/aflfast/aflfast_option.hpp) for the `enum Schedule` definition.

```cpp
enum Schedule {
    /* 00 */ FAST,                      /* Exponential schedule             */
    /* 01 */ COE,                       /* Cut-Off Exponential schedule     */
    /* 02 */ EXPLORE,                   /* Exploration-based constant sch.  */
    /* 03 */ LIN,                       /* Linear schedule                  */
    /* 04 */ QUAD,                      /* Quadratic schedule               */
    /* 05 */ EXPLOIT                    /* AFL's exploitation-based const.  */
};
```
