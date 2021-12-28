なぜfuzzufはRustに移行しなかったのか (Why we didn't move to Rust)
==

この文書は、検討したものの実行には移さなかった、fuzzufの開発言語をC++からRustへ移行する計画について、その顛末と断念した理由を説明するものです。

## サマリ

タイトルの通り、我々はRustへの移行を現時点では断念しています。理由は以下の通りです:

 - ファザーを開発する上で発明されたHierarFlowという概念がRustと適合しない。fuzzufが「任意のファジングアルゴリズムを実装できる汎用性が高いフレームワーク」を目指す上で、HierarFlowが最も合理的な設計を可能にする概念だと我々は信じている。したがって、HierarFlowを利用することのほうがfuzzufにとっては重要であると判断している。
 - Rustの言語としての利点や、付属するパッケージマネージャ・ビルドツールの強力さは魅力的な一方、すでに累積されたC\+\+のコードを全て捨ててまで移行するのは合理的でない。また、C\+\+が持つ、既存のファジングアルゴリズムの移植のしやすさも無視はできない。

## なぜC++を使い始めたか

我々は、fuzzufを開発し始める際、開発言語としてC\+\+を選択しました。

fuzzufの目的は、任意のファジングアルゴリズムをこのフレームワーク上で簡単に実装・改造できるようにし、ファジングアルゴリズムという研究分野全体で、コードベースの共通化・再利用性の向上を図ることです。

したがって、既存のファジングアルゴリズムの内、研究上の重要性が高いものはfuzzufに実装されているべきであり、必然的に再実装が容易な言語を選択することになります。

そして、そのような重要性の高いファジングアルゴリズムの大多数は、CないしはC\+\+によって実装されています。具体例としては、AFL [^afl]およびそれを（コード）ベースとして提案されたアルゴリズム群（AFLFast [^aflfast], MOpt [^mopt], REDQUEEN [^redqueen], AFLSmart [^aflsmart], AFLGo [^aflgo], IJON [^ijon], FairFuzz [^fairfuzz], AFL\+\+ [^aflpp]など）や、libFuzzer [^libfuzzer]およびそれをベースとして提案されたアルゴリズム群（Entropic [^entropic], NEZHA [^nezha]), VUzzer [^vuzzer], honggfuzz [^honggfuzz]などが挙げられます。

また、多くのファザーがCやC\+\+で書かれていることは、fuzzufのメインのユーザーであるファジングアルゴリズムの研究者たちも、CやC\+\+を開発言語として使用したい（あるいは少なくとも使用できる）ことを意味しています。通常、フレームワークの言語は、ユーザーが使用する言語に基づいて決定されるべきです。

ここで、我々がC言語ではなくC\+\+を選択したのは、単純にC++の方が言語機能が充実しているためです。複雑なアルゴリズムでは、動的なメモリ管理や数学的な計算を行う必要が出てくる可能性があり、それらをC言語で実装するのは大変です。

更に、AFLをコードベースにする派生アルゴリズムはC言語を使用しつづけざるをえず、それによって実装コストが増大してしまうことがあるように、fuzzuf上で実装されるアルゴリズムたちは、fuzzufが選択した開発言語を使い続けることになります。我々は、このことを念頭に置き、機能が全て実装されている中では最新バージョンであるC\+\+17を使用することを決定しました。

C\+\+(17)でファザーを記述することは、C言語で書く場合と比べて移植可能性を減少させることを意味するので、もしかすると、これはファザーを商業において応用する際には好ましくない決定かもしれません。しかし、fuzzufの1番の関心は純粋なファジングアルゴリズムの研究にあるため、移植可能性よりも言語の利便性を優先しています。

## Rustの魅力

我々がC\+\+を選択した一方で、近年、Rustで記述されたファザーが徐々に現れ始めたように見えます。そもそも、ファザーのみならず、ソフトウェアの開発全般において、CまたはC\+\+からより安全性の高いRustへ開発言語を移行しようという動きがあるのは間違いありません。そして、ファザーの開発言語についても、多数派の人々がCやC\+\+からRustに移行する動きがこれから起きてもおかしくないと考えています。CやC\+\+からRustに移行することには、**ファジングという分野**固有の動機があるとは思いませんが、Rustで開発することによってファザーの脆弱性のみならずバグも減少させられることを考えれば、自然なことでしょう。

また、Cargoのエコシステムが優秀であり、C\+\+のようにビルド環境・ビルドスクリプトを独自に構築し、メンテナンスし続ける労力が著しく減少することも、Rustの利点と言えるでしょう。

更に、fuzzufはC\+\+17を使用しているため、おそらく組み込み分野やカーネル以下のレイヤで活用することが、純粋なC言語で書かれているファザーに比べて難しくなっていると考えられます。Rust for Linuxなどの取り組みを見るに、Rustに移行することは、この問題を解決しえるという点でも非常に魅力的です。

## 検討開始時期

注意しなければならないこととして、Rustへの移行を本格的に検討し始めたのは、fuzzufにAFL, libfuzzerが実装された後です。そもそも、fuzzufが一番始めに試みたのは、AFLの再現です。前述の通り、実装すべき既存のファジングアルゴリズムの多くがAFLから派生しているため、AFLを移植することは最優先事項でした。

実は、fuzzufは、「もっとも汎用性が高く任意のファジングアルゴリズムを実装できるようにするには、フレームワークはどのような設計であるべきか」という問いに答えを出すべく、AFLをいくつかのパターンで実装しています。その中でHierarFlowという概念が生み出されました。その後、2番目に実装が進められたlibfuzzerやVUzzerなどを踏まえてブラッシュアップされたのが今のHierarFlowです。

Rustへの移行を検討することになったのはそれよりも後であるため、Rustへの移行にあたっては「HierarFlowをRustの言語機能上で実現することができるのか」や「HierarFlowはRustの言語設計の思想に反することがないまま、利便性を維持できるのか」についても考慮する必要がありました。

もちろん、よりRustに適合しており、fuzzufの目的を達成できる、HierarFlowに代わる概念が発見できれば、それを採用するつもりでしたし、場合によってはHierarflowやそれに類似した概念を放棄してでもRustに移行することを検討すべきです。

また、AFLが実装されているという事実は、移行するならばAFLをRustで再実装する必要があることを単純に意味しており、移行が、そのコストに見合うだけの価値を持っているかが焦点になりました。

## HierarFlowの重要性

Rustに移行するにあたって、最も大きな障壁は間違いなくHierarFlowを再現するのかどうかという点でした。これについて答えを出すには、そもそもなぜfuzzufはHierarFlowを導入したのかについて少し考える必要があります。HierarFlowがRustよりも重要な概念であり、Rustの言語設計とは相反する機能を持つならば、Rustへの移行は断念せざるを得ません（そして、実際にそのように判断しています）。一方で、HierarFlowがRustに適合する概念であったり、あまり重要でないため破棄してもいいと判断するならば、Rustへの移行を優先すべきです。

したがって、他ドキュメントと重複した内容が含まれるかもしれませんが、ここにHierarFlowの設計者がHierarFlowによって何を解決しようとしたのかについて記載します。そうすることによって、我々がHierarFlowを必要とした理由を明確にします。

前述の通り、fuzzufの目的は、任意のファジングアルゴリズムをこのフレームワーク上で簡単に実装・改造できるようにすることです。特に、世に公開されている研究成果の中には、既存のファザーのコードを改造することで、より良い性能を得たものが多く存在しています [^aflfast] [^mopt] [^entropic]。

例えば、AFLは特に膨大な数の派生アルゴリズムを持っています。多くの派生アルゴリズムは、AFLに対して直にパッチを当てる形で実装されていますが、fuzzufの目標は、パッチという手段を用いずに、これらすべてを簡単に再実装できるようにすることです。このためには、アルゴリズムに対してどんな変更を加える場合にも、変更の必要がないコードはできる限りそのまま再利用でき、変更部分のみを実装すればすぐに動かせるように、fuzzufを設計する必要がありました。結果として生まれたのがHierarFlowという概念です。

一例として、以下のような擬似コードを考えてみましょう:

```
select_seed(algo_state) {
  // algo_stateを参照してmutateするseedを決める
  mutate(algo_state, algo_state.next_seed_to_mutate())
}

mutate(algo_state, seed) {
  // algo_stateを参照して何らかのmutationを行う
  // 例えば以下ではalgo_stateが入力中の位置を決定してbitflipする
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // algo_stateを何らかの形で更新
}
```

mutation-basedなファジングにおいては、一般的なコードパターンでしょう。ここに、様々な変更を加えることを考えます。ただし、前述の通り、パッチを当てて上書きするのではなく、"派生アルゴリズム"という形で、元のコードと変更後のコード双方を実行できるようにします。

例えば、`mutate`の内容を変えることが考えられるでしょう。この場合、単純に関数として記述するならば、以下のようになります:

```
select_seed(algo_state) {
  mutate(algo_state, algo_state.next_seed_to_mutate())
}

mutate(algo_state, seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}

select_seed2(algo_state) {
  mutate2(algo_state, algo_state.next_seed_to_mutate())
}

mutate2(algo_state, seed) {
  byteflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // algo_stateを何らかの形で更新
}
```

この時、「元のコードを維持する」という制約上、関数`select_seed`, `mutate`それぞれに対して、`select_seed2`, `mutate2`という新しい関数を用意せざるを得ません。しかしながら、見ての通り、それらの関数はほとんど同じコードをコピー・ペーストしたものです。

これに対しては、関数がfirst-class objectであるような言語や、あるいは関数ポインタ・ラムダ式を扱える言語では、部分的に改善することが可能かもしれません。その場合、以下のような実装になるでしょう:

```
select_seed(algo_state) {
  // algo_stateを参照してmutateするseedを決める
  // この時、どのようなmutationを行うのかも関数オブジェクトとして渡す
  apply_mutate(algo_state, algo_state.next_seed_to_mutate(), algo_state.next_mutation())
}

apply_mutate(algo_state, seed, mutate_func) {
  mutate_func(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // algo_stateを何らかの形で更新
}
```

しかし、このような形で対応できる変更は限られています。例えば、今回の例では、`bitflip`, `byteflip`のどちらも、入力位置という単一の引数しか取りませんが、辞書やその他特別な引数を必要とするミューテーションも考えられます。あるいは、ミューテーションを1種類・1度しか適用しないとは限りません。同一のシードに対して複数種類のミューテーションをそれぞれ適用し、適用した回数だけPUTを実行することがあります。単純に実装をしている限り、これら全ての変更を、できるだけ少ない差分で実現することは不可能に近いです。この対応方法は、変更の内容を知っているからこそできる設計であるということです。

更に、こうして処理を一般化するために、関数オブジェクトやコールバック関数を用いれば用いるほど、可読性は下がり、具体的にどのようなコードがどのタイミングで実行されるか、そしてそのコードはどこで定義されているかが非常に見えづらくなります。

あるいは、以下のような実装を考えた人もいるかもしれません:

```
select_seed(algo_state) {
  // どのようなmutationを行うのかも関数オブジェクトとして渡す
  // mutationを行う関数内部では、executeやupdateについても、実装を行う
  // ここでは、bitflipかbyteflipどちらかが選択される
  mutate <- algo_state.next_mutation()
  mutate(algo_state, algo_state.next_seed_to_mutate())
}

bitflip_mutate(algo_state, seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}

byteflip_mutate(algo_state, seed) {
  byteflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // algo_stateを何らかの形で更新
}
```

ミューテーション関数を好きに定義できるため、さきほどの実装例よりも、こちらのほうが、柔軟性が高くなっているのは確かです。しかしながら、ミューテーション関数の内部を全て記述する必要があるということは、新しくミューテーション関数を定義するたびに、PUTの実行や`update_state`の呼び出しなど、後続の処理も記述する必要があります。これはコードの再利用性に欠いていると言えるでしょう。

また、別の問題点としては、今、関数オブジェクトとしてカスタマイズが可能なのは、`mutate`だけになっています。結果として、`update_state`のみに変更を加えたい場合であっても、ミューテーション関数を変更する必要が生じます。あるいは、シードの選択をカスタマイズすることや、そもそも「シードの選択、ミューテーション、実行、状態の更新」という流れを持たないアルゴリズムの実装は、この設計においては難しいと言えます。Hybrid Fuzzing [^qsym]などにおいては、上述の典型的な流れを持たないことは十分に考えられます。こういった特殊な流れを持つアルゴリズムの存在は、オブザーバパターンの採用なども難しくします。

このように、今まで説明してきたような単純な実装パターンは、表現力に限界があり、全てのファジングアルゴリズムを最低限実装できる表現力を持ちつつ、変更差分ができるだけ小さくなるような設計になっているとは言えません。

ここで登場するのがHierarFlowです。HierarFlowの使用方法については、他の文書を見てください。これまで説明してきた設計の問題に関連するHierarFlowの特徴は以下のようにまとめられます: 

 1. HierarFlowはルーチンに親子関係を設け、親ルーチンから子ルーチンを好きなタイミングで好きなだけ呼べるようにする。
 2. ルーチンAが、ルーチンBを子として持つための条件は、「Aが呼び出しに用いる型と、Bが呼び出される際に用いる型が一致していること」だけである。
 3. 各ルーチンは、条件を満たす子ルーチンをいくつでも持つことができる。子ルーチンが複数存在する場合には、基本的には一番始めに子として登録したものから、子ルーチンが順番に呼ばれる。
 4. 各ルーチンはクラスインスタンスとして表現され、メンバ変数を保持できる。したがって、ルーチン自体が状態を持つことができる。

特に、最小限の変更で差分を実装するために重要な性質は、2.および4.です。

さきほどの擬似コードをHierarFlow上で表現するとどのようになるか、擬似コードで説明しましょう。HierarFlow上でコードの流れを定義するには、ルーチン内容の定義およびルーチン同士の接続の定義が必要です。擬似コードでは、以下のようになるでしょう:

```
// ルーチンの定義

select_seed() {
  // algo_stateを参照してmutateするseedを決める
  // algo_stateは、その参照をselect_seedがメンバ変数として持っている
  // したがって、引数には登場しない
  call_successors(
      algo_state.next_seed_to_mutate()
  )
}

mutate(seed) {
  // algo_stateを参照としてメンバ変数で持っている
  bitflip(seed, algo_state.next_pos_to_flip())
  call_successors(seed)
}
  
execute(seed) 
  feedback <- execute PUT with seed
  call_successors(seed, feedback)
}

update_state(seed, feedback) {
  // algo_stateを参照としてメンバ変数で持っている
  ... // algo_stateを何らかの形で更新
}

// フローの定義(A -> BでBをAの子ルーチンにする)

select_seed -> mutate -> execute -> update_state
```

ここで、注目すべき点は2点です:
  1. 各ルーチンは、明示的にどの関数を呼び出すかを記載せず、代わりに`call_successors`を用いて「子ルーチンを呼び出すこと」を記述します。
  2. 通常の関数では、`algo_state`を引数として、呼び出す関数に渡し続ける必要がありますが、各ルーチンがメンバ変数を持てることによって、引数に渡す必要がなくなります。

1.の利点は明らかで、例えばmutateを変更したくなった場合は、mutateのルーチンを新しく用意した上で、フローの定義において、新しいルーチンに繋ぎ変えるだけで良くなります。更に、ルーチン間の呼び出す型さえ一致していれば、フローの構造を変更することも容易なため、以下のような形で、ミューテーションを増やすことも、置き換えることも容易です:

```
bitflip_mutate(seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  call_successors(seed)
}

byteflip_mutate(seed) {
  // algo_stateを参照としてメンバ変数で持っている
  bitflip(seed, algo_state.next_pos_to_flip())
  call_successors(seed)
}

select_seed -> [
   bitflip_mutate -> execute -> update_state,
  byteflip_mutate -> execute -> update_state
]
```

また、仮にミューテーションごとに、update関数で行う処理が異なる場合や、変更したくなった場合でも、適切にupdateルーチンを定義し、フローを定義しなおせば十分です:

```
update_state_for_bitflip(seed, feedback) {
  ... // algo_stateを何らかの形で更新
}

update_state_for_byteflip(seed, feedback) {
  ... // algo_stateを何らかの形で更新
}

select_seed -> [
   bitflip_mutate -> execute -> update_for_bitflip,
  byteflip_mutate -> execute -> update_for_byteflip
]
```

このように、フローの設計にはセンスが問われますが、HierarFlowを用いることで、差分ができる限り小さくなるように「処理の途中」だけを変更することが可能になります。

2.の利点は、「本当にルーチン同士で受け渡すべき、実行のたびに変化しえる値」以外を、ルーチンの呼び出しから隠蔽できることにあります。上述の例では、`algo_state` が隠蔽される値です。`algo_state`は、アルゴリズム全体の状態を管理する変数であり、確かにほとんどのルーチンにおいて必要とされる値な一方で、`algo_state`が動的に複数生成されることはあまり考えづらく、常に単一のインスタンスを参照できればそれで十分です。すなわち、通常、この値は実行中に変化するものではなく、引数として渡す必要はありません。

しかしながら、HierarFlowを用いずに実装している例においては、関数 `execute` の内部で、`algo_state`を必要とする関数 `update_state` を呼び出すため、`execute` 自身も`algo_state`を引数として受け取る必要が生じます（グローバル変数は使わないという前提です）。この現象は、アルゴリズムを部分的に変更する上では、非常に厄介です。常に渡し続ける必要のある値が、引数として登場するため、関数のシグネチャがそれによって左右されます。`execute`自身が `algo_state`を一切必要としていないならば、`execute`単体は全く別のアルゴリズムの実装にも再利用できた可能性があるにも関わらず、不必要な引数 `algo_state` を受け取らざるを得ないことによって、再利用が不可能になってしまうのです。

更に、部分的にアルゴリズムを変更する際の典型的な実装パターンとして、「`algo_state`の型`AlgoState`を拡張するために、`DerivedAlgoState`を定義する。そのうえで、`mutate`や`update_state`を一部別の定義に置き換える」というものがあります。この時、静的型付けな言語においては、`algo_state`を引数として取っていた関数は、全て型を変更する（コピーして別の関数を用意する）必要が生じます。自身は`algo_state`を必要としていない関数 `execute` すらもコードの変更の必要があります。

「言語によっては、基底クラスの参照やポインタを持つことにすれば、変更の必要はないのではないか」と考えた人もいるかも知れません。すなわち、

```
// DerivedAlgoStateはAlgoStateの派生クラス

select_seed(AlgoState& algo_state) {
  mutate(algo_state, algo_state.next_seed_to_mutate())
}

mutate(AlgoState& algo_state, Seed& seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed)
}
  
execute(AlgoState& algo_state, Seed& seed) {
  feedback <- execute PUT with seed
  update_state(algo_state, seed, feedback)
}

update_state(AlgoState& algo_state, Seed& seed, Feedback& feedback) {
  ... // algo_stateを何らかの形で更新
}
```

のように定義しておけば、

```
select_seed_derived(DerivedAlgoState& algo_state) {
  mutate_derived(algo_state, algo_state.next_seed_to_mutate())
}

mutate_derived(DerivedAlgoState& algo_state, Seed& seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  execute(algo_state, seed) // 以降AlgoStateの参照として扱われる
}
```

のように部分的な変更で済むだろうということです。確かに、これで対処はできますが、`update_state`のみを変更したい場合、ダウンキャストが発生します:

```
update_state_derived(AlgoState& algo_state, Seed& seed, Feedback& feedback) {
  DerivedAlgoState& derived_algo_state = algo_state; // ダウンキャストせざるを得ない
  ... // algo_stateを何らかの形で更新
}
```

これらの問題点に対処できているのが、HierarFlowの利点と言えるでしょう。反対に、「全てのアルゴリズムを維持し、再利用性をできるだけ高くする」というモチベーションがなければ、定期的にリファクタリングを行えばよく、このような独特な概念は必要ないでしょう。

## RustでHierarFlowを実装する際の問題点

RustでHierarFlowを実現する際、大きな問題となるのは、「Rustではミュータブルな参照を複数持つことができない」という1点のみです。これにより、各ルーチンが、引数として渡す必要のない値の参照をメンバ変数として持つことが難しくなっており、型のシグネチャにそのような値が含まれ得ます。

ここで検討すべき事項は2つあります。1つは、そもそも「引数で渡す必要のない値が引数に含まれているのはそれほど悪いことか」ということです。これについては非常に議論の余地があると思っていますが、これまで説明してきたように「我々は含まれないほうが良いと考えている」が答えになります。実際、上述の例において、`algo_state`以外の、呼び出される関数全てに渡し続けなければならない値が後から生じた時、リファクタリングや設計が非常に面倒になるでしょう。

もう1つは、「引数でなくてよい値を引数にしない」という目的を達成する方法が本当にないのかということです。実は、2通りほど、解決策を検討しました。ただし、どちらもデメリットが存在しており、採用することはできませんでした。以下に、具体的にどのような解決策なのかを記録しておきます。

#### a. Rc\<RefCell\<T\>\>

Rustでミュータブルな参照を複数箇所で利用する際は、`Rc<RefCell<T>>`を用いるのが1つの選択肢でしょう。しかし、引数でなくてよい値を使用するたびに、`borrow`, `borrow_mut` を使わなくてはならないのは、単純に骨が折れます。また、親ルーチンは必ず`call_successors`を呼び出す前に、借用した参照を破棄する必要があります。親ルーチンが `borrow_mut` を呼び出している状態で、`call_successors`経由で呼び出された子ルーチンが、`borrow`ないしは`borrow_mut`を呼び出すことが考えられるからです。このルールは非常に忘れやすく、実行時のエラーを招きやすいでしょう。コンパイル時に借用のエラーに気づきやすいというRustの利点が失われています。

#### b. マクロによる隠蔽

大前提として、グローバル変数を使わず、`Rc<RefCell<T>>`も使わないとなると、ミュータブルな参照は引数経由で渡さざるを得ません。すなわち、Rustにおいては、HierarFlowを用いて実装する場合にも、上述したような擬似コードではなく、以下のような擬似コードにならざるを得ません:

```
// ルーチンの定義

select_seed(algo_state) {
  call_successors(
      algo_state, algo_state.next_seed_to_mutate()
  )
}

mutate(algo_state, seed) {
  bitflip(seed, algo_state.next_pos_to_flip())
  call_successors(algo_state, seed)
}
  
execute(algo_state, seed) {
  feedback <- execute PUT with seed
  call_successors(algo_state, seed, feedback)
}

update_state(algo_state, seed, feedback) {
  ... // algo_stateを何らかの形で更新
}

// フローの定義(A -> BでBをAの子ルーチンにする)

select_seed -> mutate -> execute -> update_state
```

そして、このような実装にした場合には、途中のルーチンを入れ替えた際にダウンキャストせざるを得ないなどの問題がやはり発生します。

しかし、Rustには強力なマクロが存在しており、これらを隠蔽することはできなくはありません。すなわち、

```rust
#![hierarflow_routines(
  share_by_all={ algo_state : AlgoStateTrait }
)]
mod routines {

  struct select_seed {}
  impl HierarFlowCallee for select_seed {
    fn on_call(&mut self) {
      self.call_successors(
        get_algo_state!().next_seed_to_mutate()
      );
    }
  }
  ...
}
```

のような形で記述しておくことで

```rust
mod routines {
  struct select_seed {}
  impl HierarFlowCallee for select_seed {
    fn on_call<T>(&mut self, algo_state : &mut T) 
      where T : AlgoStateTrait 
    {
      self.call_successors(
        algo_state.next_seed_to_mutate(),
        algo_state
      );
    }
  }
  ...
}
```

という形で展開され、ルーチンの使用時にgenerics `T`に型が代入されることで、見かけ上のコードおよび実際の定義から、`AlgoState`を隠蔽するというような方法です。これによって、`AlgoState`の代わりに`DerivedAlgoState`を使用したくなった場合にも、既存のコードをほとんど何も考えず再利用することができます。

しかしながら、マクロで処理を隠蔽し、内部実装をブラックボックスにすることは、明らかに健全とはいえません。マクロによって内部実装を一切気にすることなく、実装が簡単になるのであれば、我々はもう少し導入に前向きだったでしょう。実際には、これらのマクロに起因したコンパイルエラーや実行時エラーにユーザーが気づけないことはないとは言い切れず、ユーザビリティに支障をきたしかねないため、この解決策を採用することもありませんでした。


#### :information_source: 議論の余地 

もしかすると、ここまで読んできた読者の皆さんの中には、ここまで検討してきたHierarFlow導入のための解決策よりも優れたものを思いついた人がいるかも知れません。あるいは、そもそもHierarFlowよりも良い概念や慣習を思いついた人がいるかも知れません。短期的な計画では、我々はRustには移行しないという決断を下していますが、中長期的には再度検討すべきであると考えています。

もし、何か良いアイデアを持っている方がいれば、ぜひGitHubのissueでそれについて聞かせてください。

## C\+\+に実装されたHierarFlowの問題点

余談にはなりますが、C\+\+におけるHierarFlowの問題点として、「ノードの定義とフローの定義が離れてしまいやすい」というものがあります。HierarFlowNodeのインスタンスのコンストラクトと、HierarFlowNode同士を繋げる実際のフローの定義は、ノードの数が多くなればなるほど、コード上で遠ざかってしまうのです。例えば、AFLのHierarFlowの定義を見ても、察しが付くかもしれません。その他のアルゴリズムでは、2つの定義が、よりはるか遠くに位置している例もあります。このことは、フローの定義を眺めることを少し面倒にしてしまっています。

（結局実現できませんでしたが）Rustにおいては、マクロを利用することによって、これを解決できる点が魅力的です。

例えば、AFLのHierarFlowは、以下のような形で、ノードのコンストラクトとフローの定義を同時に書けていたでしょう:

```rust
  build_hierarflow! [
    SelectSeed {} [ 
      ConsiderSkipMut {},
      RetryCalibrate {},
      TrimCase {},
      CalcScore {},
      ApplyDetMuts apply_det_muts {} [
        BitFlip1 {} -> ExecutePUT {} [
                         NormalUpdate {},
                         ConstructAutoDict {}
                       ],
        BitFlipOther {} -> ExecutePUT {} -> NormalUpdate {},
        ...
      ],
      ApplyRandMuts apply_rand_muts {} [
        Havoc { stage_max_multiplier: 256 } -> ExecutePUT {} ->  NormalUpdate {},
        Splicing { stage_max_multiplier: 32 } -> ExecutePUT {} ->  NormalUpdate {},
      ],
      AbandonEntry abandon_entry {},
      
      maybe_goto! [
          apply_det_muts -> abandon_entry,
          apply_rand_muts -> abandon_entry
      ]
    ]
  ]
```

将来的には、C\+\+においても、ノードのコンストラクトとフローの定義を同時にできるような記法・設計に変更していくかもしれませんが、現在の仕様においてはいくつか問題点があり、現時点では困難です。

## 参考文献

[^afl]: Michal Zalewski. "american fuzzy lop" https://lcamtuf.coredump.cx/afl/

[^libfuzzer]:  "libFuzzer – a library for coverage-guided fuzz testing." https://llvm.org/docs/LibFuzzer.html

[^aflfast]:  Marcel Böhme, Van-Thuan Pham, and Abhik Roychoudhury. 2016. Coverage-based Greybox Fuzzing as Markov Chain. In Proceedings of the 23rd ACM Conference on Computer and Communications Security (CCS’16).

[^vuzzer]: Sanjay Rawat, Vivek Jain, Ashish Kumar, Lucian Cojocar, Cristiano Giuffrida, and Herbert Bos. 2017. VUzzer: Application-aware Evolutionary Fuzzing. In the Network and Distribution System Security (NDSS’17).

[^mopt]: Chenyang Lyu, Shouling Ji, Chao Zhang, Yuwei Li, Wei-Han Lee, Yu Song, and Raheem Beyah. 2019. MOpt: Optimized Mutation Scheduling for Fuzzers. In Proceedings of the 28th USENIX Security Symposium (Security'19).

[^nezha]: Theofilos Petsios, Adrian Tang, Salvatore Stolfo, Angelos D. Keromytis, and Suman Jana. 2017. NEZHA: Efficient Domain-Independent Differential Testing. In Proceedings of the 38th IEEE Symposium on Security and Privacy (S&P'17).

[^qsym]: Insu Yun, Sangho Lee, Meng Xu, Yeongjin Jang, and Taesoo Kim. 2018. QSYM : A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing. In Proceedings of the 27th USENIX Security Symposium (Security'18).

[^aflgo]: Marcel Böhme, Van-Thuan Pham, Manh-Dung Nguyen, and Abhik Roychoudhury. Directed Greybox Fuzzing. In Proceedings of the 24th ACM Conference on Computer and Communications Security (CCS'17).

[^ijon]: Cornelius Aschermann, Sergej Schumilo, Ali Abbasi, and Thorsten Holz. 2020. IJON: Exploring Deep State Spaces via Fuzzing. In Proceedings of the 41st IEEE Symposium on Security and Privacy (S&P'20).

[^aflpp]: Andrea Fioraldi, Dominik Maier, Heiko Eißfeldt, and Marc Heuse. 2020. AFL++: Combining Incremental Steps of Fuzzing Research. In Proceedings of the 14th USENIX Workshop on Offensive Technologies (WOOT'20).

[^redqueen]: Cornelius Aschermann, Sergej Schumilo, Tim Blazytko, Robert Gawlik, and Thorsten Holz. 2019. REDQUEEN: Fuzzing with Input-to-State Correspondence. In the Network and Distribution System Security (NDSS'19).

[^aflsmart]: Van-Thuan Pham, Marcel Böhme, Andrew E. Santosa, Alexandru Răzvan Căciulescu, Abhik Roychoudhury. 2019. Smart Greybox Fuzzing. In IEEE Transactions on Software Engineering (TSE'1).

[^entropic]: Marcel Böhme, Valentin J.M. Manès, and Sang K. Cha. 2020. Boosting Fuzzer Efficiency: An Information Theoretic Perspective. In Proceedings of the 28th ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering (ESEC/FSE'20).

[^fairfuzz]: Caroline Lemieux and Koushik Sen. 2018. FairFuzz: A Targeted Mutation Strategy for Increasing Greybox Fuzz Testing Coverage. In Proceedings of the 33rd ACM/IEEE International Conference on Automated Software Engineering (ASE'18).

[^honggfuzz]: "honggfuzz" https://honggfuzz.dev/
