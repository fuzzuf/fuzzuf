# fuzzufにおけるAFLの実装

## 参考にしたオリジナルのAFLの実装

 - バージョン: 2.57b
 - コミット:   https://github.com/google/AFL/commit/fab1ca5ed7e3552833a18fc2116d33a9241699bc

## ディレクトリ構成

fuzzufにおいてAFLは `include/fuzzuf/algorithms/afl` および `algorithms/afl` 以下で実装されています。AFLは派生アルゴリズムを多く持つ性質上、ほとんどの構成クラスがテンプレートによって実装されます。したがって、それらのクラスの宣言・定義は全て `include/fuzzuf/algorithms/afl` 以下のヘッダーファイル内にあります。

特に、それらのテンプレートクラスの宣言は `include/fuzzuf/algorithms/afl` 直下のファイル、定義は `include/fuzzuf/algorithms/afl/templates` 直下のファイルで行われています。これは、明確にfuzzufのコーディング規約で定まっているルールというわけではありません。AFLは、元々通常のクラスとして実装されていたものをテンプレートクラスとして実装し直しており、git上の差分を少なくするためにはそのような構成にせざるをえなかったという歴史的な経緯によります。今後のリファクタリングよって、`templates` サブディレクトリを削除し、ファイルをまとめることを検討しています。

## HierarFlowの定義

`include/fuzzuf/algorithms/afl/templates/afl_fuzzer.hpp` で定義されているAFLのHierarFlowは以下のようになっています:

```cpp
    fuzz_loop << (
         cull_queue
      || select_seed
    );

    select_seed << (
         consider_skip_mut
      || retry_calibrate
      || trim_case
      || calc_score
      || apply_det_muts << (
             bit_flip1 << execute << (normal_update || construct_auto_dict)
          || bit_flip_other << execute.HardLink() << normal_update.HardLink()
          || byte_flip1 << execute.HardLink() << (normal_update.HardLink()
                                               || construct_eff_map)
          || byte_flip_other << execute.HardLink() << normal_update.HardLink()
          || arith << execute.HardLink() << normal_update.HardLink()
          || interest << execute.HardLink() << normal_update.HardLink()
          || user_dict_overwrite << execute.HardLink() << normal_update.HardLink()
          || auto_dict_overwrite << execute.HardLink() << normal_update.HardLink()
         )
       || apply_rand_muts << (
               havoc << execute.HardLink() << normal_update.HardLink()
            || splicing << execute.HardLink() << normal_update.HardLink()
          )
       || abandon_node
    );
```

これらのノードの内、`bit_flip1`, `bit_flip_other`などのノードのルーチンは、`include/fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp` で宣言されています。`normal_update`, `construct_auto_dict`などのノードのルーチンは、`include/fuzzuf/algorithms/afl/afl_update_hierarflow_routines.hpp` で宣言されています。それらのノード以外のルーチンは、 `include/fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp` で宣言されています。

## 整合性とパフォーマンスのテスト

fuzzufのAFL実装は、過去に、オリジナルのAFLと動作が同一になることが確認されており、ほとんど完全に再現されていると言えます。過去に行ったテストの詳細については以下のリポジトリを確認してください:

* https://github.com/fuzzuf/fuzzuf-afl-artifact

## 変更部分

現在の実装は、上述のテストを行った時点での実装から大きく変化しました。中でも特筆すべき変更は、AFL派生アルゴリズムを念頭に置き、ミューテーションhavocをカスタマイズ可能な設計にしたことです。その結果として、現在のfuzzuf上のAFLは、オリジナルAFLと全く同じ実行結果を得ることはできなくなっています。

しかしながら、ミューテーションの内容自体には一切差分がなく、havoc内部で各種類のミューテーションが選択される確率は元のAFLと変わらないはずであるため、統計上の性質は一切変わっていないと考えられます。

## 未実装部分

現時点では、オリジナルのAFLにある以下の機能が実装されておらず、今後実装される予定です:

  - persistent mode
  - resume mode
  - QEMU mode
  - 並列ファジング
  - SIGUSR1のハンドル

## AFL派生アルゴリズムの定義

おそらく、fuzzufのユーザーの中には、fuzzufを利用してAFLを改造したいと考える人が多くいるでしょう。
具体例はAFLFastの実装に譲りますが、ここにどのようにすればAFLの派生アルゴリズムを独自に定義できるかを簡単にまとめておきます。

### 1. Tagの定義

まず始めに、作成する派生アルゴリズム向けに、Tagと呼ばれる空の構造体を定義してください(例えば、`struct AFLDerivedTag {};`)。
例えば、AFL向けのTagは `include/fuzzuf/algorithms/afl/afl_option.hpp` で定義されています:

```cpp
struct AFLTag {};
```

fuzzufでは、Tagを利用することで、定義されている定数の値を任意に変更することができるようになります。詳しくは、`include/fuzzuf/algorithms/afl/afl_option.hpp` 内のコメントを参照してください。

### 2. AFLTestcaseの継承

1つのシードに対して、AFLが持っている情報に加えて独自に何らかの情報をもたせたい場合には、`AFLTestcase`を継承した新しいTestcaseクラス（例えば `AFLDerivedTestcase` ）を定義してください。この時、`using`によるエイリアス宣言を使って、`AFLDerivedTestcase::Tag` を宣言してください。具体的には以下のような形になるでしょう:

```cpp
struct AFLDerivedTestcase : public AFLTestcase {
  using Tag = AFLDerivedTag;

  ...
```

### 3. AFLStateの継承

アルゴリズム全体で、AFLが持っている情報に加えて独自に何らかの情報をもたせたい場合には、`AFLState`を継承した新しいStateクラス（例えば `AFLDerivedState` ）を定義してください。

### 4. AFLStateのメンバ関数の特殊化・HierarFlowRoutineの追加

派生アルゴリズムが、AFLと同一のアルゴリズムの流れを持つものの、異なる処理をする必要がある場合には、メンバ関数のオーバーライドやテンプレートクラスの特殊化を利用してください。

あるいは、派生アルゴリズムが、AFLとは異なる独自のアルゴリズムの流れを持つ場合は、その処理に相当するHierarFlowRoutineを定義してください。この場合、`AFLFuzzerTemplate<AFLDerivedState>::BuildFuzzFlow` を定義し、アルゴリズムの流れについても定義をしてください。
