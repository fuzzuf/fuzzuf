# IJON

## IJONとは

[IJON](https://github.com/RUB-SysSec/ijon/)[^ijon]は、[SysSec](https://informatik.rub.de/syssec/)によって提案された、PUTがファザーに新しいフィードバックを返せるようにするアノテーション手法、およびそれらのフィードバックに対応したファザーです。有名なファザーの多くは、PUTからコードカバレッジをフィードバックとして受け取ることでプログラムの新しい挙動を見つけようとする、カバレッジガイデッドファザーに種別されます。典型的なカバレッジガイデッドファザーには以下のような弱点があります: 

- コードカバレッジがどのような順序によって獲得されたかについて気にしていない。例えば、「関数Aが実行された直後に関数Bが実行されること」が引き起こす条件となっているようなバグがあったとする。ファザーは、バグを引き起こす入力と「関数Bの実行の後に関数Aの実行を引き起こすような入力」を区別できないため、後者のみを試してしまい、バグを見落とす可能性がある。より突き詰めていえば、そもそも「関数Aと関数Bの両方を通らせる入力」と「関数Aを通らせる入力および関数Bを通らせる入力の２つ」を区別できず、どちらか一方を既に試している場合には、もう一方を試さないようなアルゴリズムが多い。
  - コードカバレッジの種類の中で、パスカバレッジを用いた場合には、この問題にはある程度対処できる。しかし、実行パスが異なる入力を過剰に保存してしまった場合には、同じファジング結果になる似たような入力を保持しやすくなり、ファジングキャンペーン全体の効率が低下してしまうというトレードオフがある。このトレードオフを自動で良い塩梅に調節するというのは難しい。
- コードカバレッジでは気づくことのできない内部状態の変化が存在しうる。例えば、IJONの論文に記載されている通り、ゲームにおけるプレイヤーの座標などを考えてみると分かりやすい。プレイヤーが画面上のどの位置に存在しているかは、ゲームの新しい状態を発見する上で重要になる可能性が高い。プレイヤーが画面右下にいるよりも画面左上にいるほうが、新しいイベントの発生座標に近いかもしれない。しかしながら、コードカバレッジだけをフィードバックとしている場合は、どちらの座標にいても同じフィードバックが返されることになる。

IJONは、これらの問題点に対処できるシンプルな解決策として、「PUTに対して人の手でアノテーションを行う」という方法を提案しています。PUTをソースコードからビルドしカバレッジの取得を計装する際、人間がソースコードにアノテーションを加えることで、PUTがファザーに与えるフィードバックをカスタマイズできます。IJONが提供するアノテーションには様々なものがあり、人間が重要な内部状態だと考えるものを明示するために用います。例えば「ある変数の最大値をフィードバックに記録する」、「ある2変数の差の最小値を記録する」といったアノテーションが可能です。

実際には、IJONのファザーはAFLをベースとして実装されているため、PUTが返すフィードバックは、(Hashed) Edge Coverageであり、共有メモリを経由してファザーに受け渡されます。したがって、IJONは、ソースコードに記述できるアノテーションを、具体的には共有メモリに対して値を書き込む関数およびマクロとして実装しています。これらのマクロや関数は、計装ツールがEdge Coverageを計装する際に、一緒にコンパイルされます。

このようにIJONは、AFLベースかつ実用的なファジングにおいて求められるハーネス記述用のインターフェイスを備えており、fuzzufの応用可能性の向上を目的としてfuzzuf上に実装されています。

## CLI上での使用方法

IJONのファザーを利用するには、まず、計装ツールを用いてアノテーションをほどこしたPUTを準備する必要があります。
fuzzufには計装ツールが存在していないため、[IJONのリポジトリ](https://github.com/RUB-SysSec/ijon/)からオリジナルの計装ツールをビルドしてください。

IJONのファザーは、ビルドした計装ツールによってPUTを作成した後、`fuzzuf`をインストールした状態で、

```bash
fuzzuf ijon -i path/to/initial/seeds/ path/to/PUT @@
```

で起動できます。指定可能なグローバルなオプションはAFLと同様です。
AFLのオプションについては[AFL/algorithm_ja.md#cli上での使用方法](/docs/algorithms/afl/algorithm_ja.md#cli上での使用方法)を参照してください。

使用できるIJONのローカルオプションは以下です:

- `--forksrv 0|1`
  - 1が指定された場合、fork server modeが有効になります。 デフォルトで有効です。


## 使用例

ビルドした計装ツールおよびfuzzufに実装されたIJONのファザーをテストする簡単な方法は、IJONのリポジトリにある[test.c](https://github.com/RUB-SysSec/ijon/blob/master/test.c)および[test2.c](https://github.com/RUB-SysSec/ijon/blob/master/test2.c)をビルドし、ファジングしてみることです。ただし、test.cは、現在の最新コミット(56ebfe34)では正常にビルドできないため、以下の変更を加えてください。

```diff
diff --git a/llvm_mode/afl-rt.h b/llvm_mode/afl-rt.h
index 616cbd8..28d5f9d 100644
--- a/llvm_mode/afl-rt.h
+++ b/llvm_mode/afl-rt.h
@@ -45,14 +45,14 @@ void ijon_enable_feedback();
 void ijon_disable_feedback();

 #define _IJON_CONCAT(x, y) x##y
-#define _IJON_UNIQ_NAME() IJON_CONCAT(temp,__LINE__)
+#define _IJON_UNIQ_NAME IJON_CONCAT(temp,__LINE__)
 #define _IJON_ABS_DIST(x,y) ((x)<(y) ? (y)-(x) : (x)-(y))

 #define IJON_BITS(x) ((x==0)?{0}:__builtin_clz(x))
 #define IJON_INC(x) ijon_map_inc(ijon_hashstr(__LINE__,__FILE__)^(x))
 #define IJON_SET(x) ijon_map_set(ijon_hashstr(__LINE__,__FILE__)^(x))

-#define IJON_CTX(x) ({ uint32_t hash = hashstr(__LINE__,__FILE__); ijon_xor_state(hash); __typeof__(x) IJON_UNIQ_NAME() = (x); ijon_xor_state(hash); IJON_UNIQ_NAME(); })
+#define IJON_CTX(x) ({ uint32_t hash = ijon_hashstr(__LINE__,__FILE__); ijon_xor_state(hash); __typeof__(x) IJON_UNIQ_NAME = (x); ijon_xor_state(hash); IJON_UNIQ_NAME; })

 #define IJON_MAX(x) ijon_max(ijon_hashstr(__LINE__,__FILE__),(x))
 #define IJON_MIN(x) ijon_max(ijon_hashstr(__LINE__,__FILE__),0xffffffffffffffff-(x))
diff --git a/test.c b/test.c
index 50b1b05..aa022f6 100644
--- a/test.c
+++ b/test.c
@@ -3,6 +3,7 @@
 #include<assert.h>
 #include<stdbool.h>
 #include <stdlib.h>
+#include <stdint.h>
```

例えば、test.cをビルドしたバイナリは、以下のようにしてファジングできます:

```bash
$ (path_to_ijon)/llvm_mode/afl-clang-fast (path_to_ijon)/test.c -o test
$ mkdir /tmp/ijon_test_indir/ && echo hello > /tmp/ijon_test_indir/hello
$ fuzzuf ijon -i /tmp/ijon_test_indir/ ./test
```

test.cは標準入力から入力を受け付けるため、`@@`を指定する必要がないことに注意してください。

test.cおよびtest2.cを見れば、アノテーションの付け方のイメージを掴むことができますが、
より詳しいアノテーションの使い方については、IJONのREADMEおよびソースコードを参照してください。

## アルゴリズム概要

IJONはAFLの処理をほとんど残したまま、処理を追加する形で実装されています。大まかには、AFLとの差分は以下のとおりです:

- havocミューテーションのいくつかのケースが改変されている。
- AFLのシードキューとは別に、IJON専用のシードキューを持つ。
  - 共有メモリ上の64bit非負整数の配列のそれぞれの要素について、IJONのシードキューは「その要素へ最も大きい値を記録したシード」を保存する。
- ファジングループの冒頭で、ランダムに処理の分岐が発生する。
  - 80%の確率でIJONのシードキューからシードが選択される。この場合、直後にhavocステージに移行し、havocミューテーションを一定回数行うとファジングループの先頭に戻る。
  - 20%の確率でAFLのシードキューからシードが選択される。この場合は、元のAFLと同じ流れでミューテーションを行う。
- PUT実行後の、PUTから得られたフィードバックを元にしたシードキューの更新で、IJONのシードキューも更新する。
  - 20%の確率でAFLが選択された場合でも、IJONのシードキューは更新する。
- 定数の値がいくつか変更されている。

## 参考文献

[^ijon]: C. Aschermann, S. Schumilo, A. Abbasi, and T. Holz. 2020. IJON: Exploring Deep State Spaces via Fuzzing. In Proceedings of the 41st IEEE Symposium on Security and Privacy (S&P’20).
