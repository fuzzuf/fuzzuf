# libFuzzer

## libFuzzerとは

[https://llvm.org/docs/LibFuzzer.html](https://llvm.org/docs/LibFuzzer.html)

libFuzzerはLLVMプロジェクトのcompiler-rtのライブラリの1つとして提供されているgreybox fuzzingの実装である。AFLと同じく広く使われており、現在のファジング研究のベースとなっていることからfuzzufでの再実装を行なった。

libFuzzerはcorpusに記録されている入力値をもとにmutationで新しい入力値を作り、その入力値でfuzzingの対象を実行し、カバレッジ等を調べて珍しいパスを通っていたり、珍しい振る舞いをしていれば新しい入力値をcorpusに追加するという操作を繰り返す。ここからわかるようにlibFuzzerは大雑把にはAFLとよく似た手順で動くfuzzerである。ただしAFLと比較して以下の点が大きく異なっている:

* 入力値のランダムな範囲を整数値がテキストで書かれた物と見做してパースし、演算を行ってからテキストに戻して元の位置に書き直すmutatorを持つ(ChangeASCIIInt)
* 2つの入力値を引数にとって両者をランダムに混ぜ合わせるmutatorを持つ(Crossover)
* LLVMの`-fsanitize-coverage=trace-cmp`を使って比較演算のログを取り、比較の両辺の値を辞書として用いるmutatorを持つ(CMP)
* 辞書の単語を使って作った入力値がcorpusに追加された場合にその単語が自動で登録されていくPersistent Auto Dictionaryを持つ
* mutationを所定の回数(デフォルト 100回)実行して作った新しい入力値を実行してもcorpusに追加すべき実行結果が得られなかった場合、決められた回数(デフォルト 5回)まで同じ入力値に対してmutationをやり直す
* 入力値の特定の範囲だけをmutationするように指示することができる(Mask)
* LLVM 10以降では実行結果にどの程度の価値があるかを表すenergyを、その実行結果がどの程度珍しいパスを通っているか等(feature)から求める。corpusから入力値を選ぶ際にある入力値が選ばれる確率はenergyによって変化する(entropic scheduling)。LLVM 9以前では1つ以上のfeatureを新たに見つけている実行結果に対して、後から見つかった物程高い確率で選ばれるような重み付け(vanilla scheduling)がなされる。
* featureの種類には最大値が設けられていて、新しいfeatureを発見した際に既知のfeatureが最大数に達していた場合、featureのうち最も多くの実行結果に共通して現れている物(abundant feature)は以後無視されるようになる。無視されたfeatureはenergyの計算にも影響しなくなる。これによって一度珍しいと判断された実行結果も後から同じような実行結果が頻繁に見つかると価値が低下し、価値が無くなると(energy == 0)corpusから削除される。
* 過去の実行結果と同じfeatureを得られるより短い入力値を発見した場合、corpusの要素をより短い方で置き換える(reduce)

libFuzzerはmutationで作った新しい入力値を引数としてハーネスと呼ばれる関数を呼び出す。ユーザーはlibFuzzerが生成した入力値を使ってfuzzingの対象となる関数を呼び出すハーネスを実装し、対象の関数を含むライブラリとlibFuzzerをリンクする。このようなfuzzingの方法は子プロセスを生成する古典的なfuzzerの実装と比較して性能面で有利である(子プロセスの生成は一般に時間がかかる)。

fuzzingの対象とfuzzerの実装自体が同じプロセス内に存在するため

* fuzzer自体のカバレッジがカウントされないようにする必要がある
* サニタイザが異常を報告した時、それがfuzzing対象から報告された物かfuzzer自体から報告されたものか区別できる必要がある

といった問題が生じる。

libFuzzerは前者を達成するために`-fsanitize-coverage=edge`を付けてビルドされたfuzzingの対象と`-fsanitize-coverage=edge`を付けずにビルドされたlibFuzzerのライブラリをリンクする。このとき、libFuzzer側のインライン関数がfuzzingの対象のビルド時にコンパイルされる事が無いように注意深く実装されている。ハーネスのカバレッジが記録される点は気にしない。

後者を達成する為にlibFuzzerはハーネスの実行前と実行後にサニタイザが抱えている情報を漁り、必要に応じて書き換えている。LLVMのサニタイザの実装は将来に渡って互換性が保たれるAPIではない(し、実際時々変わっている)が、libFuzzer自体がLLVMの一部でLLVMと一緒にバージョンアップしている為、対応するバージョンのLLVMのサニタイザと組み合わせられれば良い、というスタンスでお構いなしに中身を漁っている。

前述のfeatureの動作で見たように、オリジナルのlibFuzzerではバージョンによって細かな動きの違いがある。例えば、乱数生成器はLLVM 8まではmt19937が使われていて、LLVM 9以降はminstd_randが使われている。

## libFuzzerの仕組み

libFuzzerは以下の擬似コードで示す操作を行う。

ここで`initial_input`は初期シード、`target`はfuzzingを行う対象、`total_count`はターゲットを実行する回数、`mutation_depth`は同じ入力値に対してmutationを行う回数を表す。

```cpp
count = 0;
// 1回以上現れているが出現回数が少ない「珍しい」featureのIDの配列
unique_feature_set = {}
// 過去に現れたfeatureの出現回数を保持する連想配列
global_feature_freqs = {}
corpus = {}
// 全ての初期シードについて
for( input in initial_inputs ) {
  // ターゲットを一度実行し
  exec_result = execute( target, input );
  // 実行結果をcorpusに追加
  add_to_corpus( corpus, exec_result, input );
}
// 入力値が選ばれる確率を更新
dist = update_distribution( corpus );
// 試行回数がtotal_countに達するまで
while( count < total_count ) {
  // mutation_depth(libFuzzerではデフォルト5回)に達するまで 
  for( i = 0; i < mutation_depth; ++i ) {
    // corpusから入力値を1つ選び
    [old_exec_result,input] = corpus.select_seed();
    // 入力値のmutationを行い
    mut_input = mutate( dist, input );
    // ターゲットを実行
    exec_result = execute( target, mut_input );
    // 実行結果からfeatureを求め
    features = collect_features( old_exec_result, exec_result, unique_feature_set, global_feature_freqs );
    // 新しいfeatureを発見していたら
    if( is_interesting( features ) ) {
      // 実行結果と入力値をcorpusに追加
      corpus.add( exec_result, mut_input );
      // 入力値が選ばれる確率を更新
      dist = update_distribution( corpus );
      // 試行回数をインクリメント
      ++count;
      // corpusに実行結果を追加した場合mutation_depthに達していなくてもループを抜ける
      break;
    }
    else {
      // 試行回数をインクリメント
      ++count;
    }
  }
}
```

libFuzzerはターゲットの実行結果のうち「注目すべき特徴」をfeatureと呼び、IDを与えて扱う。
featureとして扱われる特徴は基本的にedge coverageのedgeのインデックスとそのedgeを通過した回数が用いられる。

上の擬似コードでは`collect_features()`で現在のシードの実行結果`exec_result`からfeatureを収集する。`collect_features()`はfeatureが見つかるたびに`unique_feature_set`と`global_feature_freqs`を更新していく。

`collect_features()`で得られた`features`の中に新しいfeatureがある場合にはその実行結果`exec_result`とmutationで得られた入力値`mut_input`をcorpusに追加する。新しいfeatureが含まれるかどうかは`is_interesting()`が行い、`features`の中に`unique_feature_set`にある「珍しい」featureが1つ以上含まれているかで判定される。最後に次の入力値を選ぶ確率`dist`を`update_distribution()`で更新する。

`update_distribution()`の挙動にはvanilla schedulingとentropic schedulingの2種類が存在し、fuzzufのlibFuzzer実装ではデフォルトで前者を用いる。vanila schedulingでは単純に「より最近見つかった物が高い確率で選ばれる」分布が用いられる。一方、entropic schedulingではシードの実行結果の価値を評価して、その評価が高い実行結果ほど次の`select_seed()`で選ばれやすくなるように乱数の分布を更新する。entropic schedulingで計算されるこのシードの実行結果の価値を表す値をenergyと呼び、`collect_features()`でfeatureの収集と同時に次の観点で計算する:

* 見つかった「珍しい」featureの数
* 初期シードからこの入力値に至るまでにmutationを行った回数
* 実行時間がどの程度平均から外れているか

entropic schedulingではenergyを考慮した結果、次のような方針でシードを選択する:

* 珍しいfeatureを出した入力を集中的に選択する
* mutationの度に新しいfeatureの発見を繰り返している入力を集中的に選択する
* 同じだけのfeatureが見つかるならより短時間で処理できる入力を優遇する
