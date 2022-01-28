# American Fuzzy Lop

## AFLとは

https://github.com/google/AFL

AFL(American Fuzzy Lop)は、2013年にMichał Zalewskiによって開発されたカバレッジガイデッドファザーです。AFLは、自身の持つキューに保持されているシードを1つ選択し、それに改変を加えることで未知の実行パスを発見しようとする、いわゆるミューテーションベースドファザーと呼ばれる種のファザーです。言い換えれば、AFLはシードに対して遺伝的アルゴリズムを適用します。

AFLの特筆すべき点は、多くのアルゴリズムの基礎となっていることでしょう。AFLの実装を一部改変することで、性能の向上[^1] [^2] [^3]、動作対象となるPUTや環境の拡張[^4] [^5]や特殊な用途への転換[^6] [^7]を達成した様々な研究が存在しています。このようにAFLは現在のファジング研究のベースとなっていることからfuzzuf上で再実装されました。

## CLI上での使用方法

fuzzufをインストールした状態で、

```bash
fuzzuf afl --in_dir=path/to/initial/seeds/ -- path/to/PUT @@
```

で起動できます。その他、指定可能なオプションは以下の通りです:

 - グローバルなオプション(全てのファザーで共通)
   - `--out_dir=path/to/output/directory/`
     - クラッシュシードなど、ファザーによって生成される出力がすべて入るディレクトリを指定します。
     - このオプションが指定されない場合は、`/tmp/fuzzuf-out_dir/` に出力されます。
   - `--exec_timelimit_ms=1234`
     - 1回のPUTの実行に対する時間制限をミリ秒単位で指定できます。
     - このオプションが指定されない場合は、時間制限は1秒になります。
   - `--exec_memlimit=1234`
     - 1回のPUTの実行で使用できるメモリ量の制限を、メガバイト単位で指定できます。
     - このオプションが指定されない場合は、使用できるメモリ量は、64bit環境では25MB、32bit環境では50MBになります。
   - `--log_file=path/to/log/file`
     - ログ出力や、デバッグモードでビルドした場合のデバッグ出力を記録するファイルを指定します。
     - 指定されない場合は、標準出力に出力されます。
 - ローカルなオプション(AFLのみで有効)
  - `--dict_file=path/to/dict/file`
    - 追加の辞書ファイルへのパスを指定します。

その他、fuzzuf上での実装の詳細については [implementation_ja.md](/docs/algorithms/afl/implementation_ja.md) を参照してください。

## アルゴリズム概要

AFLの大まかな処理の流れは以下のようになります:

  1. ユーザーが与えた初期シードそれぞれについて、そのシードを入力としてPUTを実行し、フィードバック（実行パス、終了ステータス、実行時間）を記録する。また、初期シードをすべてキューに保存する。
  2. 以下のループをプロセスが終了するまで永遠に繰り返す:
  
      1. キューの先頭からシードを1つ取り出す。
      2. 取り出したシードに対して、前処理を行う。具体的には、シードの最小化（同じフィードバックを得られる入力で、できるだけ小さなものをヒューリスティックに作る）と、シードの*良さ*の計算を行う。
      3. 取り出したシードに対して、様々なミューテーションを行い、生成されたバイト列を入力としてPUTを実行する。
          - 生成されたバイト列を入力としてPUTを実行した時、PUTがこれまで見つかっていなかった実行パスを通過した場合には、その入力を価値があるものとみなしてキューに追加する。

## (Hashed) Edge Coverage

上述のアルゴリズムでは、「PUTがこれまで見つかっていなかった実行パスを通過したかどうか」を判断する必要があります。しかしながら、一般に、実行パスすべてを記録し、厳密に実行パスの一致不一致を判定するのは非常に計算効率が悪くなります。そのため、AFLは、実行パスの代わりにControl Flow Graph上の辺ひとつひとつについて、その辺を過去に通過したことがあるかを記録することで対処しています。この辺に対する記録は、ソフトウェアテストの文脈においてEdge Coverageと呼ばれます。

通常、AFLは、PUTをコンパイルする際にEdge Coverageを計測するためのコードを挿入し、共有メモリ経由でその情報が取得できるようにしておきます。この行為を計装(instrumentation)と呼びます。具体的には、コンパイラは以下のような処理を行います:
  
  1. PUTが、プログラム開始時に、環境変数で指定された共有メモリをアタッチするようにコードを挿入する。また、アタッチした共有メモリをPUT内部で参照できるように、グローバル変数 `u8* __afl_area_ptr` を定義し、そこに共有メモリのアドレスを代入するコードも挿入する。
  2. Control Flow Graphの各頂点 `v` に対して16ビット整数の乱数 `r(v)` を割り当てる。
  3. 辺 `e: u -> v` に対して、 `h(e) = r(v) ^ (r(u) >> 1)` を計算する。
  4. PUTが、辺 `e: u -> v` を通った際に、`__afl_area_ptr[h(e)]++` を実行するようにコードを挿入する。
      - 実際には、indirectなジャンプに対応するため、グローバル変数 `u32 __afl_prev_loc` を定義した上で、各Basic Block `v` の先頭に `__afl_area_ptr[r(v) ^ __afl_prev_loc]++`、末尾に `__afl_prev_loc = r(v) >> 1` を実行するコードを挿入する。

これを見ると分かる通り、AFLはEdge Coverageを完全に計測しているわけではなく、以下の近似を行うことで計測の効率化を試みています:
  - 各辺を通過した回数を記録するカウンターは8ビットの変数として宣言されているので、256回以上ある辺を通過した場合には情報が不正確になる。特に、ある辺を通過した回数が256の倍数だった場合には、通過していないものと見做される。
  - Control Flow Graphの各辺に対して割り当てるIDはハッシュを用いて計算している。結果、IDはユニークではないため、衝突し得る。辺のIDが衝突した場合には、それらの辺は同じカウンターを使用してしまう。

PUTはこのようにしてEdge Coverageを記録しますが、AFL側でEdge Coverageを使用する際には、更に「各カウンターについて、その値を2のべき乗に丸める」という近似が行われます。具体的には、以下のルールに基づいて、値を丸めます:
 - 0は0、1は1、2は2のままになる。
 - 3は4に丸められる。
 - \[4, 7\]に含まれる値は8に丸められる。
 - \[8, 15\]に含まれる値は16に丸められる。
 - \[16, 31\]に含まれる値は32に丸められる。
 - \[32, 127\]に含まれる値は64に丸められる。
 - \[128, 255\]に含まれる値は128に丸められる。

直感的には、「ある辺を似たような回数通っている場合には、似たような実行パスである」と考えられるため、この近似によって、特にカウンターの値が大きい場合に、値の微小な差を無視することができます。また、2べきの値にまとめることによって、「ある辺をある回数通るような実行パスがこれまでに存在したかどうか」という情報を、1ビットで表現できるようになります。AFLは、各辺、各0から128までの2のべき乗に対して、この情報を示すフラグを持ち、いずれかのフラグが初めて立ったとき、実行に用いた入力をキューに保存します。

## シードの選択

AFLは、すべての保存したシードを、順番にミューテーションの対象にします。ただし、一定の確率でミューテーションをスキップすることがあります。スキップするかどうかは、シードが*お気に入り*であるかどうかなどに依存します。

シードが*お気に入り*であるとは、ある共有メモリのカウンターが存在して、以下の条件を満たす事をいいます:
  - そのシードを入力としてPUTを実行すると、そのカウンターは非ゼロな値をとる
  - カウンターを非ゼロにする他のシードに比べて、（シード長）x （シードを入力とした際のPUTの実行時間）の値が最小

## ミューテーション

AFLが適用するミューテーションには、大きく分けて以下の2種類があります:

#### 決定的なミューテーション

ビットフリップ・加算減算・単語の挿入などのミューテーションがこの種類に該当します。
これらのミューテーションは、シードのあり得る全ての入力位置に対して、あり得る全てのパラメータで適用されるため、生成されるバイト列の集合は何度やっても変わりません。結果として、生成されたバイト列を入力としてPUTを何度実行しても、得られるEdge Coverageは（PUTがランダムな振る舞いをしない限り）変わりません。
よって、ミューテーションの対象になっているシードに、過去に決定的なミューテーションを適用していた場合は、これらのミューテーションを適用することは二度とありません。

#### 非決定的なミューテーション

havocと呼ばれるミューテーションと、splicingと呼ばれるミューテーション（遺伝的アルゴリズムにおける交叉に相当するもの）がこの種類に該当します。ランダムな入力位置にランダムな変更を行います。

ミューテーションを適用する回数は、シードに依存して変化します。より具体的には、あらかじめ計算されているシードの*良さ*に比例した回数だけhavocおよびsplicingを行います。シードの選択も含めて考えると、AFLは重み付きラウンドロビン方式のような形で、シードに対するミューテションを行っていると言えます。

## 参考文献

[^1]: Marcel Böhme, Van-Thuan Pham, and Abhik Roychoudhury. 2016. Coverage-based Greybox Fuzzing as Markov Chain. In Proceedings of the 23rd ACM Conference on Computer and Communications Security (CCS’16).
[^2]: Chenyang Lyu, Shouling Ji, Chao Zhang, Yuwei Li, Wei-Han Lee, Yu Song, and Raheem Beyah. 2019. MOpt: Optimized Mutation Scheduling for Fuzzers. In Proceedings of the 28th USENIX Security Symposium (Security'19).
[^3]: Andrea Fioraldi, Dominik Maier, Heiko Eißfeldt, and Marc Heuse. 2020. AFL++: Combining Incremental Steps of Fuzzing Research. In Proceedings of the 14th USENIX Workshop on Offensive Technologies (WOOT'20).
[^4]: Sergej Schumilo, Cornelius Aschermann, Robert Gawlik, Sebastian Schinzel, and Thorsten Holz. 2017. kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels. In Proceedings of the 26th USENIX Security Symposium (Security'17).
[^5]: Google Project Zero. "WinAFL" https://github.com/googleprojectzero/winafl
[^6]: Cornelius Aschermann, Sergej Schumilo, Ali Abbasi, and Thorsten Holz. 2020. IJON: Exploring Deep State Spaces via Fuzzing. In Proceedings of the 41st IEEE Symposium on Security and Privacy (S&P'20).
[^7]: Marcel Böhme, Van-Thuan Pham, Manh-Dung Nguyen, and Abhik Roychoudhury. Directed Greybox Fuzzing. In Proceedings of the 24th ACM Conference on Computer and Communications Security (CCS'17).

