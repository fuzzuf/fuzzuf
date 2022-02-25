# fuzzufでのlibFuzzerの実装

ここではfuzzufでのlibFuzzerの実装について解説する。

## 標準的なlibFuzzerの組み方

オリジナルのlibFuzzerの`Fuzzer::Loop()`に相当するファザーは[include/fuzzuf/algorithms/libfuzzer/create.hpp](/include/fuzzuf/algorithms/libfuzzer/create.hpp)の`createRunone()`として実装されている。標準的なlibFuzzerとして使う場合にはこの関数を利用することでfuzzufでのlibFuzzer実装が利用できる。

## libFuzzerを構成するHierarFlowノード

HierarFlowでlibFuzzerを表現するために以下のようなノードを実装している。それぞれのノードについての詳細についてはソースコードのコメントやDoxygenで生成されたドキュメントを参照してもらいたい。

### Mutatorノード

* [EraseBytes](/include/fuzzuf/algorithms/libfuzzer/mutation/erase_bytes.hpp)
* [InsertByte](/include/fuzzuf/algorithms/libfuzzer/mutation/insert_byte.hpp)
* [InsertRepeatedBytes](/include/fuzzuf/algorithms/libfuzzer/mutation/insert_repeated_bytes.hpp)
* [ChangeByte](/include/fuzzuf/algorithms/libfuzzer/mutation/change_byte.hpp)
* [ChangeBit](/include/fuzzuf/algorithms/libfuzzer/mutation/change_bit.hpp)
* [ShuffleBytes](/include/fuzzuf/algorithms/libfuzzer/mutation/shuffle_bytes.hpp)
* [ChangeASCIIInteger](/include/fuzzuf/algorithms/libfuzzer/mutation/change_ascii_integer.hpp)
* [ChangeBinaryInteger](/include/fuzzuf/algorithms/libfuzzer/mutation/change_binary_integer.hpp)
* [CopyPart](/include/fuzzuf/algorithms/libfuzzer/mutation/copy_part.hpp)
  * CopyPartOf
  * InsertPartOf
* [CrossOver](/include/fuzzuf/algorithms/libfuzzer/mutation/crossover.hpp)
  * CrossOver
  * CopyPartOf
  * InsertPartOf
* [Dictionary](/include/fuzzuf/algorithms/libfuzzer/mutation/dictionary.hpp)
  * Dictionary
  * UpdateDictionary

### 制御ノード

制御ノードはHierarFlowでlibFuzzerを構成するために必要な制御を行うノードである。

* [ForEach](/include/fuzzuf/algorithms/libfuzzer/hierarflow/for_each.hpp)
* [IfNewCoverage](/include/fuzzuf/algorithms/libfuzzer/hierarflow/if_new_coverage.hpp)
* [RandomCall](/include/fuzzuf/algorithms/libfuzzer/hierarflow/random_call.hpp)
* [Repeat](/include/fuzzuf/algorithms/libfuzzer/hierarflow/repeat.hpp)
* [RepeatUntilNewCoverage](/include/fuzzuf/algorithms/libfuzzer/hierarflow/repeat_until_new_coverage.hpp)
* [RepeatUntilMutated](/include/fuzzuf/algorithms/libfuzzer/hierarflow/repeat_until_mutated.hpp)
* [DoNothing](/include/fuzzuf/algorithms/libfuzzer/do_nothing.hpp)
* [Assign](/include/fuzzuf/algorithms/libfuzzer/hierarflow/assign.hpp)
* [Append](/include/fuzzuf/algorithms/libfuzzer/hierarflow/append.hpp)

### Executeノード

ExecuteノードはfuzzufのExecutorを持ち、ターゲットを入力値を使って実行し、カバレッジと標準出力、実行結果を取得するノードである。

* [Execute](/include/fuzzuf/algorithms/libfuzzer/hierarflow/execute.hpp)

### Feedbackノード

Feedbackノードは実行結果をcorpusに追加するかどうかの判断するノードを実際に追加するノードから構成される。

* [CollectFeatures](/include/fuzzuf/algorithms/libfuzzer/hierarflow/collect_features.hpp)
* [AddToCorpus](/include/fuzzuf/algorithms/libfuzzer/hierarflow/add_to_corpus.hpp)
* [AddToSolutions](/include/fuzzuf/algorithms/libfuzzer/hierarflow/add_to_solution.hpp)
* [UpdateDistribution](/include/fuzzuf/algorithms/libfuzzer/hierarflow/add_to_solution.hpp)
* [ChooseRandomSeed](/include/fuzzuf/algorithms/libfuzzer/hierarflow/choose_random_seed.hpp)

### デバッグノード

デバッグノードはHierarFlowで構成したファザーのデバッグのために利用可能なノードである。

* [Dump](/include/fuzzuf/algorithms/libfuzzer/hierarflow/dump.hpp)
* [PrintStatusForNewUnit](/include/fuzzuf/algorithms/libfuzzer/hierarflow/print_status_for_new_unit.hpp)

## 未実装部分

いくつかのlibFuzzerの機能はfuzzufでは実装されていない:

### Mutator

#### Mutate_AddWordFromTORC (CMP)

オプションCMPが有効な場合に追加されるmutatorであり、比較演算で分岐したときの情報を記録してmutationを行う。この機能を使うにはまず`-fsanitize-coverage=trace-cmp`を使って比較演算で分岐した際に何と何を何の演算子で比較したかを記録する。CMPは比較に使われた値と同じ値を入力から探し、それを条件分岐が異なる側に入るように書き換える。入力に比較したのと同じ値が入っていたからと言って、それが必ずしも比較された値そのものとは限らないが、ある程度の確率で分岐方向を変えられる事を期待する。
fuzzufでは`trace-cmp`で得られる比較演算の情報が取得できないためこのmutatorは使えない。

### Mutate_AddWordFromPersistentAutoDictionary

過去に`Mutate_AddWordFromManualDictionary`と`Mutate_AddWordFromTORC`で挿入した値のうち、新しいカバレッジの発見に繋がった物が蓄積される辞書の実装であるが、fuzzufではCMPが実装されていないため、`Mutate_AddWordFromManualDictionary`のみから入力を拾う実装になっている。

#### カスタムmutator

libFuzzerには独自のmutatorを追加する為にCustomMutatorとCustomCrossOverが用意されている。fuzzufでは特別なノードを用意するよりノードを自作して追加する方が簡単な為、これらのmutatorに対応するノードは用意していない。

### Corpus

libFuzzerはCorpusの完全な状態を永続化し、途中からfuzzingを再開する事ができるが、fuzzufの実装では入力値のみを永続化するため、永続化された情報から再開したとしても以前の状態を完全に復元する事はできない。

### Feature

#### Data Flow Trace

Data Flow TraceではLLVMのDataFlowSanitizerを使って得られるデータの移動の記録を使って入力値のどの部分が分岐に影響するかを特定する。この結果に基づいてmutationを行う範囲にマスクをかける事で、特定の分岐を抜ける入力を集中的に探すと考えられる。しかし、オリジナルのlibFuzzerの実装ではマスクの生成には繋がっておらず、この情報は有効に活用されていない。fuzzufではCMPが未実装である理由と同様に、DataFlowSanitizerに相当する情報を得る手段がないため未実装となっている。

### Executor

#### 子プロセス作成の回避

libFuzzerはfuzzingの対象とfuzzerを同じバイナリにリンクする事で子プロセス生成のコストを回避するが、これに相当するexecutorは現状fuzzufにない為、fuzzufの実装では子プロセスが作られる。

#### 共有ライブラリのサポート

libFuzzerは実行可能バイナリのedge coverageだけでなく、そこにリンクされる共有ライブラリのedge coverageも回収して結合する仕組みを持っている。fuzzufは共有ライブラリからカバレッジを取る手段がないため未実装となっている。

### Feedback

#### Leak Sanitizer

オリジナルのlibFuzzerはターゲットの実行を開始してから確保され、終了するまでに解放されなかったメモリを検知している。一方、fuzzufではLeak Sanitizer付きでターゲットがコンパイルされていればこのケースを失敗扱いにすることはできるが、失敗理由はabortになるため、メモリリークだったかどうか判別できないため、未解放のメモリ検知の情報を活用できない。

#### Stack Depth Tracing

オリジナルのlibFuzzerではLLVMのSanitizerCoverageのstack-depthを使ってターゲットがスタックをどこまで使ったかを取得するが、fuzzufでは使われたスタックの深さを取る手段がないため、未実装となっている。
