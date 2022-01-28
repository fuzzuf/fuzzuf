# libFuzzer

## libFuzzerとは

https://llvm.org/docs/LibFuzzer.html

libFuzzerはLLVMプロジェクトのcompiler-rtのライブラリの1つとして提供されているgreybox fuzzingの実装である。AFLと同じく広く使われており、現在のファジング研究のベースとなっていることからfuzzufでの再実装を行なった。

libFuzzerはcorpusに記録されている入力値をもとにmutationで新しい入力値を作り、その入力値でfuzzingの対象を実行し、カバレッジ等を調べて珍しいパスを通っていたり、珍しい振る舞いをしていれば新しい入力値をcorpusに追加するという操作を繰り返す。ここからわかるようにlibFuzzerは大雑把にはAFLとよく似た手順で動くfuzzerである。ただしAFLと比較して以下の点が大きく異なっている

* 入力値のランダムな範囲を整数値がテキストで書かれた物と見做してパースし、演算を行ってからテキストに戻して元の位置に書き直すmutatorを持つ(ChangeASCIIInt)
* 2つの入力値を引数にとって両者をランダムに混ぜ合わせるmutatorを持つ(Crossover)
* LLVMの`-fsanitize-coverage=trace-cmp`を使って比較演算のログを取り、比較の両辺の値を辞書として用いるmutatorを持つ(CMP)
* 辞書の単語を使って作った入力値がcorpusに追加された場合にその単語が自動で登録されていくPersistent Auto Dictionaryを持つ
* mutationを所定の回数(デフォルト 100回)実行して作った新しい入力値を実行してもcorpusに追加すべき実行結果が得られなかった場合、決められた回数(デフォルト 5回)まで同じ入力値に対してmutationをやり直す
* 入力値の特定の範囲だけをmutationするように指示することができる(Mask)
* LLVM 10以降では実行結果にどの程度の価値があるかを表すenergyを、その実行結果がどの程度珍しいパスを通っているか等(feature)から求める。corpusから入力値を選ぶ際にある入力値が選ばれる確率はenergyによって変化する(entropic scheduling)。LLVM 9以前では1つ以上のfeatureを新たに見つけている実行結果に対して、後から見つかった物程高い確率で選ばれるような重み付け(vanilla scheduling)がなされる。
* featureの種類には最大値が設けられていて、新しいfeatureを発見した際に既知のfeatureが最大数に達していた場合、featureのうち最も多くの実行結果に共通して現れている物(abbundant feature)は以後無視されるようになる。無視されたfeatureはenergyの計算にも影響しなくなる。これによって一度珍しいと判断された実行結果も後から同じような実行結果が頻繁に見つかると価値が低下し、価値が無くなると(energy == 0)corpusから削除される。
* 過去の実行結果と同じfeatureを得られるより短い入力値を発見した場合、corpusの要素をより短い方で置き換える(reduce)

libFuzzerはmutationで作った新しい入力値を引数としてハーネスと呼ばれる関数を呼び出す。ユーザーはlibFuzzerが生成した入力値を使ってfuzzingの対象となる関数を呼び出すハーネスを実装し、対象の関数を含むライブラリとlibFuzzerをリンクする。このようなfuzzingの方法は子プロセスを生成する古典的なfuzzerの実装と比較して性能面で有利である(子プロセスの生成は一般に時間がかかる)。

fuzzingの対象とfuzzerの実装自体が同じプロセス内に存在するため

* fuzzer自体のカバレッジがカウントされないようにする必要がある
* サニタイザが異常を報告した時、それがfuzzing対象から報告された物かfuzzer自体から報告されたものか区別できる必要がある

といった問題が生じる。

libFuzzerは前者を達成するために`-fsanitize-coverage=edge`を付けてビルドされたfuzzingの対象と`-fsanitize-coverage=edge`を付けずにビルドされたlibFuzzerのライブラリをリンクする。このとき、libFuzzer側のインライン関数がfuzzingの対象のビルド時にコンパイルされる事が無いように注意深く実装されている。ハーネスのカバレッジが記録される点は気にしない。

後者を達成する為にlibFuzzerはハーネスの実行前と実行後にサニタイザが抱えている情報を漁り、必要に応じて書き換えている。LLVMのサニタイザの実装は将来に渡って互換性が保たれるAPIではない(し、実際時々変わっている)が、libFuzzer自体がLLVMの一部でLLVMと一緒にバージョンアップしている為、対応するバージョンのLLVMのサニタイザと組み合わせられれば良い、というスタンスでお構いなしに中身を漁っている。

乱数生成器はLLVM 8まではmt19937が使われていて、LLVM 9以降はminstd\_randが使われている

このほかlibFuzzerには将来的に-fsanitize=dataflowを使って入力値のどの部分が分岐に寄与したかを調べる為の物と思われるコードが転がっているが、現状ここから得た情報は有効に活用されていない。

libFuzzerはLLVM 4でllvm本体のlib以下に実装され、LLVM 5でcompiler-rtに移動された。

## fuzzufにおける実装

[移植の状況](/docs/algorithms/libfuzzer/porting_status_ja.md)

## libFuzzerの仕組み

libFuzzerは以下の疑似コードのような手順で動く。

ここでinitial\_inputは初期シード、targetはfuzzingを行う対象、total\_countはターゲットを実行する回数、mutation\_depthは同じ入力値に対してmutationを行う回数を表す。

```
count = 0;
unique_feature_set = {}
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

libFuzzerはターゲットの実行結果のうち注目すべき特徴にIDを与えたfeatureを用いる

featureは基本的にedge coverageのedgeのインデックスとそのedgeを通過した回数から計算される

global\_feature\_freqsは過去に現れたfeatureの出現回数をfeature毎にカウントしている

unique\_feature\_setは1回以上現れているが出現回数が少ないfeatureのidを持っている

unique\_feature\_setには最大長があり、長さが最大に達している状態で新しいfeatureが見つかった場合、unique\_feature\_setの中で最も頻繁に見つかっているfeatureがunique\_feature\_setから外れる

is\_interestingはターゲットの実行結果から見つかったfeatureの中に、unique\_feature\_setに並んでいる珍しいfeatureが1つ以上含まれていた場合にtrueになる

crashedはターゲットの実行結果が正常終了以外の場合にtrueになる

実行結果は

* 見つかった珍しいfetureの数
* 初期シードからこの入力値に至るまでにmutationを行った回数
* 実行時間がどの程度平均から外れているか

に基づいてenergyが計算される

update\_distributionはenergyが高い実行結果程次のselect\_seedで選ばれやすくなるように乱数の分布を更新する
この結果libFuzzerのselect\_seedは

* 珍しいfeatureを出した入力が集中的に選択される
* mutationの度に新しいfeatureの発見を繰り返している入力が集中的に選択される
* 同じだけのfeatureが見つかるならより短時間で処理できる入力が優遇される

ような動きをする

## Mutatorノード

libFuzzerには13種類のmutatorが実装されており、新しい入力値を作る際にはそれらの中から1つを均等な確率で選んで実行する操作を100回繰り返す

実装されているmutatorは以下の通り

### EraseBytes

与えられたバイト列のランダムな位置からランダムな長さ(最大でバイト列の長さの半分)を削除する

既にバイト列が1バイト「以下」だったら何もしない


fuzzufではfuzzuf::algorithm::libfuzzer::erase_byteノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::erase_byteで処理される

### InsertByte

与えられたバイト列のランダムな位置に128バイト以下かつ最大長を超えないランダムな長さの値を挿入する

挿入される値は0x00か0xFFがランダムに選ばれる

既にバイト列が最大長だったら何もしない


fuzzufではfuzzuf::algorithm::libfuzzer::insert\_byteノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::insert\_byteで処理される

### InsertRepeatedBytes

与えられたバイト列のランダムな位置に128バイト以下かつ最大長を超えないランダムな長さの値を挿入する

挿入される値は0x00か0xFFがランダムに選ばれる

既にバイト列が最大長だったら何もしない

fuzzufではfuzzuf::algorithm::libfuzzer::insert\_repeated\_bytesノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::insert\_repeated\_bytesで処理される

### ChangeByte

与えられたバイト列のランダムな位置の1バイトをランダムな値に書き換える

バイト列が何故か最大長より長い場合は何もしない

fuzzufではfuzzuf::algorithm::libfuzzer::change\_byteノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::change\_byteで処理される

### ChangeBit

与えられたバイト列のランダムな位置のランダムな1bitを反転させる

バイト列が何故か最大長より長い場合は何もしない

fuzzufではfuzzuf::algorithm::libfuzzer::change\_bitノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::change\_bitで処理される

### ShuffleBytes

与えられたバイト列のランダムな位置から残りのバイト数以下かつ8バイト以下のランダムなバイト数の範囲をstd::shuffleする

バイト列が何故か最大長より長い場合およびバイト列が空の場合は何もしない

fuzzufではfuzzuf::algorithm::libfuzzer::shuffle\_bytesノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::shuffle\_bytesで処理される

### ChangeASCIIInt


バイト列が何故か最大長より長い場合およびバイト列が空の場合は何もしない

https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/fuzzer/FuzzerMutate.cpp#L109

ChangeASCIIInt
与えられたバイト列のランダムな位置から線形探索して最初に’0’以上’9’以下の値が見つかった位置をbegin、beginから線形探索して最初に’0’以上’9’以下でない値が見つかった位置をendとし、beginからendの範囲を先頭を最上位の位とする10進数と見做して64bit符号無し整数型の値を得る

この値に

* インクリメント
* デクリメント
* 倍にする
* 半分にする
* ランダムな値に置き換える

のいずれかの操作をランダムに選択肢して行い、beginからendの間に先頭を最上位の位として書き直す

操作によって桁が増えてbeginからendの間に収まらない場合は上の桁を捨てる

バイト列が何故か最大長より長い場合は何もしない

fuzzufではfuzzuf::algorithm::libfuzzer::change\_ascii\_integerノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::change\_ascii\_integerで処理される 

### ChangeBinInt

uint8\_t、uint16\_t、uint32\_t、uint64\_tの4種類の型から1つTが均等な確率で選ばれる

与えられたバイト列の先頭から終端-sizeof(T)の範囲のランダムな位置からsizeof(T)バイトをT型の整数と見做す

位置が先頭から64バイト以内の場合1/4の確率でその位置にバイト列の全長を書き込む

それ以外の場合はその位置の値に-10以上10以下の値を足す

書き込み時には1/2の確率でエンディアンの変換が行われる

fuzzufではfuzzuf::algorithm::libfuzzer::change\_binary\_integerノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::change\_binary\_integerで処理される

### CopyPart

1/2の確率でCopyPartOfまたはInsertPartOfを行う

#### CopyPartOf

与えられたバイト列のランダムな位置から残りの長さ以下のサイズの領域をランダムな位置にコピーする

コピーはmemmoveで行われ、コピー元とコピー先は重複する可能性がある

#### InsertPartOf

与えられたバイト列のランダムな位置から残りの長さ以下かつ最大サイズまでの残りサイズ以下のサイズの領域をランダムな位置に挿入する

fuzzufではfuzzuf::algorithm::libfuzzer::copy\_partノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::copy\_partで処理される

### CrossOver

1/3の確率でCrossOverWithの値と与えられたバイト列でCrossOver、CopyPartOf、InsertPartOfのいずれかを行う

#### CrossOver

バイト列Aとバイト列Bから交互に1バイトづつデータを取り出して並べた新しいバイト列を作る

### CopyPartOf

バイト列Aのランダムな位置から残りの長さ以下かつ最大サイズまでの残りサイズ以下のサイズの領域をバイト列Bのランダムな位置からサイズ分の領域に書き込む

#### InsertPartOf

バイト列Aのランダムな位置から残りの長さ以下かつ最大サイズまでの残りサイズ以下のサイズの領域をバイト列Bのランダムな位置に挿入する

fuzzufではfuzzuf::algorithm::libfuzzer::crossoverノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::crossoverで処理される

### ManualDict

あらかじめ用意した辞書にあるバイト列のうち1つをランダムに選び、与えられたバイト列のランダムな位置に挿入する

fuzzufではfuzzuf::algorithm::libfuzzer::static\_dictionaryノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::dictionaryで処理される

### PersAutoDict

新しいfeatureの発見に繋がった辞書の要素が自動的に追加されていく辞書にあるバイト列のうち1つをランダムに選び、与えられたバイト列のランダムな位置に挿入する

fuzzufではfuzzuf::algorithm::libfuzzer::dynamic\_dictionaryノードが担当し、fuzzuf::algorithm::libfuzzer::mutator::dictionaryで処理される
static\_dictionaryおよびdynamic\_dictionaryがdict\_entryに記録した辞書の利用記録をfuzzufではfuzzuf::algorithm::libfuzzer::update\_dictionaryノードに渡すと、fuzzuf::algorithm::libfuzzer::mutator::update\_dictionaryで辞書の要素の追加が行われる

### CMP

オプションCMPが有効な場合に追加される

この機能を使うにはまず-fsanitize-coverage=trace-cmpを使って比較演算で分岐した際に何と何を何の演算子で比較したかを記録する

CMPは比較に使われた値と同じ値を入力から探し、それを条件分岐が異なる側に入るように書き換える

入力に比較したのと同じ値が入っていたからと言って、それが必ずしも比較された値そのものとは限らないが、ある程度の確率で分岐方向を変えられる事を期待する

fuzzufではこのmutatorは使えない

### カスタムmutator

libFuzzerには独自のmutatorを追加する為にCustomMutatorとCustomCrossOverが用意されている。fuzzufでは特別なノードを用意するよりノードを自作して追加する方が簡単な為、これらのmutatorに対応するノードは用意していない

## 制御ノード

HierarFlow上でlibFuzzerを実現する為に必要な制御構文を実現する為に以下のノードを実装している

### ForEach

rangeの要素を1つづつ指定された引数にセットして、後続のノードを実行する。後続のノードはrangeの要素数と同じ回数実行される。

fuzzuf::algorithm::libfuzzer::static\_for\_eachはノードにrangeを持ち、fuzzuf::algorithm::libfuzzer::dynamic\_for\_eachは指定された引数からrangeを得る。

### IfNewCoverage

指定された引数に含まれている実行結果がadd\_to\_corpusで1回以上corpusに追加されている物だった場合後続のノードの要素を全て実行する。そうでなかった場合後続のノードの最後の要素だけを実行する。

fuzzuf::algorithm::libfuzzer::if\_new\_coverageノードが担当する。

### RandomCall

後続のノードの要素のうち最後の要素を除く1つをランダムに選んで実行し、その後最後の要素を実行する。

fuzzuf::algorithm::libfuzzer::random\_callノードが担当する

### Repeat

後続のノードのうち最後の要素を除く要素を指定された回数繰り返し実行し、その後最後の要素を実行する。

fuzzuf::algorithm::libfuzzer::static\_repeatはノードがカウンタと繰り返し回数を持ち、後続のノードを実行する度にこのノードがカウンタをインクリメントさせる。

fuzzuf::algorithm::libfuzzer::partially\_dynmic\_repeatはノードが繰り返し回数だけを持ち、引数で指定されたカウンタの値が繰り返し回数に達しない限り後続のノードを実行する。カウンタは別途Appendノードなどを使ってインクリメントしなければならない。

fuzzuf::algorithm::libfuzzer::dynmic\_repeatはノードが一切の情報を持たず、引数で指定されたカウンタの値が引数で指定された繰り返し回数に達しない限り後続のノードを実行する。カウンタは別途Appendノードなどを使ってインクリメントしなければならない
。

### RepeatUntilNewCoverage

指定された引数に含まれている実行結果がadd\_to\_corpusで1回以上corpusに追加されている物だった場合後続のノードの最後の要素を実行して処理を完了させる。それ以外の場合corpusに追加されるまで後続のノードの最後の要素以外を実行する。

fuzzuf::algorithm::libfuzzer::repeat\_until\_new\_coverageノードが担当する

### Nop

これ自体は何もしないで後続のノードを実行する。

主にnop >>より前の||で結合されたノードとnop >>より後の||で結合されたノードを明示的に異なるグループにする為に用いる。

fuzzuf::algorithm::libfuzzer::nopノードが担当する

### Assign

指定された引数に指定された値を代入する。

fuzzuf::algorithm::libfuzzer::static\_assignは指定された引数にノードが持っている値を代入する。

fuzzuf::algorithm::libfuzzer::dynamic\_assignは指定された引数に、指定された引数の値を代入する。

### Append

指定された引数に指定された値を追加する。

fuzzuf::algorithm::libfuzzer::static\_assignは指定された引数にノードが持っている値を追加する。

fuzzuf::algorithm::libfuzzer::dynamic\_assignは指定された引数に、指定された引数の値を追加する。

## Executeノード

### Execute

fuzzufのExecutorを持ち、引数で受け取った入力値を使ってfuzzingの対象を実行し、カバレッジと標準出力と実行結果を引数で指定された場所に出力する

fuzzuf::algorithm::libfuzzer::executeノードが担当し、fuzzuf::algorithm::libfuzzer::executor::executeが実際にexecutorをRunする。

## Feedbackノード

これらのノードは実行結果をcorpusに追加するかどうかの判断と実際に追加する処理を含む

### CollectFeatures

引数で受け取ったカバレッジと実行結果からfeatureを求めて引数で指定された場所に出力する。

fuzzuf::algorithm::libfuzzer::collect\_featuresノードが担当し、fuzzuf::algorithm::libfuzzer::executor::collect\_featuresが実際の計算を行う。

### AddToCorpus

引数で受け取ったfeatureに未発見のものが含まれていた場合、またはforce\_add\_to\_corpusがtrueの場合引数で指定されたcorpusに引数で指定された実行結果と入力値を追加する。

corpusに追加された実行結果はadded\_to\_corpusがtrueになる。これはIfNewCoverageノード、RepeatUntilNewCoverageノード、AddToSolutionsノードの振る舞いに影響する。

fuzzuf::algorithm::libfuzzer::add\_to\_corpusノードが担当し、fuzzuf::algorithm::libfuzzer::executor::add\_to\_corpusが実際の追加を行う。

### AddToSolutions

引数で受け取った実行結果のadd\_to\_corpusがtrueの場合引数で指定されたcorpusに実行結果と入力値を追加する。

crashed\_onlyがtrueの場合実行結果が正常終了以外の場合のみcorpusに実行結果と入力値を追加する。

AddToCorpusと異なり出力先のディレクトリを指定する事ができ、入力値を永続化する事ができる。

fuzzuf::algorithm::libfuzzer::add\_to\_solutionsノードが担当し、fuzzuf::algorithm::libfuzzer::executor::add\_to\_solutionsが実際の追加を行う。

### UpdateDistribution

引数で受け取ったcorpusの状態に基づいてcorpusの各要素がRandomChoiceノードで選ばれる確率を計算し直す。

fuzzuf::algorithm::libfuzzer::update\_distributionノードが担当し、fuzzuf::algorithm::libfuzzer::select\_seed::update\_distributionが実際の計算を行う。

### RandomChoice

引数で受け取ったcorpusのなかからランダムな1つを指定された引数にコピーする。

個々の実行結果が選ばれる確率はUpdateDistributionノードで決定される(このノードが先に実行されていなければならない)。

fuzzuf::algorithm::libfuzzer::random\_choiceノードが担当し、fuzzuf::algorithm::libfuzzer::select\_seed::select\_seedが実際の選択を行う。

## デバッグノード

主にデバッグの為にfuzzingの途中で引数の値をダンプしたりするノード

### Dump

指定された引数の内容をto\_stringを使ってシリアライズし、ノードが持つコールバックを使って出力する。

fuzzuf::algorithm::libfuzzer::static\_dumpが担当する。

### PrintSttusForNewUnit

引数で受け取った実行結果の内容をlibFuzzerのFuzzer::PrintStatusForNewUnitと同じ形式でノードが持つコールバックを使って出力する。

fuzzuf::algorithm::libfuzzer::print\_status\_for\_new\_unitが担当する。

## 標準的なlibFuzzerの組み方

test/algorithms/libfuzzer/execute.cpp の中で組み立てているものがオリジナルのlibFuzzerのFuzzer::Loop()に近い処理になっている

