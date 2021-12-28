# fuzzufにおけるAFLFastの実装

fuzzuf上でのAFLFastは、[AFLの実装](/docs/algorithms/AFL/algorithm_ja.md)を再利用しつつ、AFLFastに必要な以下の部分のみをテンプレート化またはオーバーライドすることによって実現しています。
- `ApplyDetMutsTemplate<AFLFastState>::operator()`
- `AbandonEntryTemplate<AFLFastState>::operator()`
- `AFLFastState::AddToQueue`
- `AFLFastState::UpdateBitmapScoreWithRawTrace`
- `AFLFastState::SaveIfInteresting`
- `AFLFastState::DoCalcScore`
- `AFLFastState::ShowStats`

## オプションについて
AFLFastでは[ドキュメント](/docs/algorithms/AFLFast/algorithm_ja.md)にあるパワースケジューラを指定することが可能であり、特に指定がない場合は`FAST`が使用されます。

### C++から呼び出す場合
`AFLFastSetting::AFLFastSetting`インスタンスを生成する際に、`schedule`引数に指定してください。`enum Schedule`の定義は[include/fuzzuf/algorithms/aflfast/aflfast_option.hpp](/include/fuzzuf/algorithms/aflfast/aflfast_option.hpp)にあります。

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

