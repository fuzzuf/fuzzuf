# fuzzuf

![fuzzuf-afl-exifutil](/docs/resources/img/fuzzuf-afl-exifutil.png)

**fuzzuf**（**fuzz**ing **u**nification **f**ramework）は、DSLによるファジングループ（fuzzing loop）の柔軟な設定と拡張性を兼ね備えた、ファジングツール（ファザー）記述のためのフレームワークです。

fuzzufのビルド方法とチュートリアルは、[TUTORIAL_ja.md](/TUTORIAL_ja.md)を参照してください。


## fuzzufの目的 (Why use fuzzuf?)

fuzzufは、数あるファザー内で定義されるファジングループを、DSLによる記法でブロックを組み合わせるように表現することで、既存のアルゴリズムに対する拡張性を保ちながら、ファジングループ内の挙動を柔軟に定義可能にするためのフレームワークです。
マルチプラットフォームに対応可能な、AFL、VUzzer、libFuzzerを含む複数のファザーが定義済みで、ユーザーによるさらなる拡張を可能としています。

## fuzzufの利点（Benefits of using fuzzuf）
fuzzuf上でファザーを記述することには、大きくわけて4つの利点があります。

- ループ内の、それぞれのプリミティブを組み合わせた記述ができる  
fuzzufでは、ループ中のステップ（段階）であるプリミティブを、ビルディングブロックのように組み合わせることで、ファジングループを構成します。  
それぞれのブロックは付け加え、取り外し、置き換え、そして再利用が可能なので、ファジングループのモジュール性を高く保つことが可能です。

- ユーザー定義可能な、ファジングループの柔軟な構成  
既存のファジングフレームワークでは、ファジングループが固定、またはフレームワーク内にハードコードされており、ユーザーが実装したいファザーごとに、ループの挙動を変更することができませんでした。  
fuzzufでは、細分化されたそれぞれのファジングプリミティブに対してルーティンを割り当て実装し、ループの構造をユーザーが望むように、柔軟に記述・変更することが可能です。

- オリジナルのファザーとその派生の比較が容易  
研究者やプログラマが既存のファザーをフォークし、それを元に新しいファザーを作ることは珍しくありません。実際、数多のファジング研究により、多くのAFL派生ファザーが生まれてきました。  
fuzzufのDSLによるファジングループの記述は、前述のビルディングブロック的な特性を利用し、既存のファジングプリミティブをまるごと（あるいは一部）再利用することで、開発コストを大幅に下げることができます。  
さらに、DSLの差分を見ることで、その派生物がオリジナルに対しどのような変更を加えたのか、ということがひと目でわかるようになります（これはレビュアー、あるいは他のファジング研究者にとっても大きい利点と言えるでしょう）。

- AFL派生ファザー実装のためのテンプレート
fuzzufでは、AFLがファザーの（C\+\+）テンプレートとしても利用可能です。これは、既存および新しいAFL派生ファザーを、fuzzuf上で実装・レビューするためのコストが大幅に下げられていることを意味します。
例として、fuzzufのAFLFastは、このテンプレートをもとに実装されています。元のAFLとの差分は、二つのルーティンとの実装と、ファザーの状態を記録する構造体にとどまっており、テンプレートが提供するフロー定義は変更せず、そのまま利用しています。

## fuzzufの強み（HierarFlow）

fuzzufではファジングループ記述に、**HierarFlow**という独自のDSLを用います。C\+\+言語の上で実装されており、木構造を模した文法を用いて、ファジングループをビルディングブロックのように組み合わせて記述できるのが特長です。
これにより、ファジングループの構造が明確に示せるため、既存、および新しいファザーを読みやすく書くことができます。
例として、fuzzufに実装済みであるAFLファザーは、入力のミューテーター（決定的およびランダム）、PUT実行、クラッシュを起こす入力を保存する機能などに細分化されます。fuzzufでは、それぞれの細分化されたプリミティブを、C\+\+コードのルーティンとして記述し、HierarFlow演算子で適切につなげることで、ファジングループを構成しています。
また、ルーティン内の挙動を自由に記述可能なため、ルーティン（実際には木構造におけるノード）をどのようにして連鎖させるかを意識して書くことで、ファジングループの拡張性は非常に高いものとなります。

HierarFlowのドキュメントは、近日中に追加される予定です。

## 実装済みファザー一覧

現在、fuzzufでは、以下のファザーがデフォルトで実装されています。
ファザーの説明・fuzzufのCLIを通した使い方については、それぞれのドキュメントを参照ください。
また、CLIからfuzzufを使う場合、fuzzuf全体で共通のグローバルオプションと各ファザー固有のローカルオプションは、`--`で区切られることに留意してください。

### AFL

CGF（Coverage-guided Greybox Fuzzer）を代表する汎用ファザーの、fuzzufにおける再実装です。
fuzzufではAFLが、単体のファザーとしてだけでなく、派生ファザー実装のためのテンプレートとしても提供されています。
このAFLの実装は[fuzzuf/fuzzuf-afl-artifact](https://github.com/fuzzuf/fuzzuf-afl-artifact)で示しているようにオリジナルのAFLを可能な限り再現しており、かつ同等以上実行速度を実現しています。
- [紹介とCLIの使い方](/docs/algorithms/AFL/algorithm_ja.md)
- [アルゴリズム概要](/docs/algorithms/AFL/algorithm_ja.md#アルゴリズム概要)
- [アルゴリズム詳細](/docs/algorithms/AFL/algorithm_ja.md##hashed-edge-coverage)
- [fuzzufでの実装](/docs/algorithms/AFL/implementation_ja.md)

### AFLFast

上記のAFLテンプレートを利用した、AFLFastの実装です。パワースケジューリングの調整により、オリジナルのAFLからパフォーマンスの向上を図っています。
- [紹介とCLIの使い方](/docs/algorithms/AFLFast/algorithm_ja.md)
- [アルゴリズム概要](/docs/algorithms/AFLFast/algorithm_ja.md#アルゴリズム概要)
- [アルゴリズム詳細](/docs/algorithms/AFLFast/algorithm_ja.md#パワースケジュールについて)
- [fuzzufでの実装](/docs/algorithms/AFLFast/implementation_ja.md)

### VUzzer

PUTのコントロールフローやデータフローを解析することでプログラムの構造を推測する、ミューテーションベースドファザーです。
オリジナルのVUzzerではlibdft64を用いてデータフロー解析を行なっていましたが、モダンな環境では動作しないという問題がありました。そこで、fuzzufでは改造された[PolyTracker](https://github.com/fuzzuf/polytracker)を使用し、モダンな環境でもVUzzerを動作可能としています。
- [紹介とCLIの使い方](/docs/algorithms/VUzzer/algorithm_ja.md)
- アルゴリズム概要
- アルゴリズム詳細
- fuzzufでの実装

### libFuzzer

LLVMプロジェクトの、compiler-rtのライブラリのひとつとして提供されている、CGFです。
- [紹介とCLIの使い方](/docs/algorithms/libFuzzer/manual.md) (英語)
- [アルゴリズム概要](docs/algorithms/libFuzzer/algorithm_ja.md)
- [アルゴリズム詳細](/docs/algorithms/libFuzzer/algorithm_ja.md#libfuzzerの仕組み)
- [fuzzufでの実装](/docs/algorithms/libFuzzer/algorithm_ja.md#fuzzufにおける実装)

### Nezha

ひとつの入力値を用いて、複数の異なる実装を持つPUTに対する実行結果の差分から、プログラムの不具合の発見を試みる、libFuzzerを元としたファザーです。
fuzzufにおいて、差分によるファジング（differential fuzzing）のアルゴリズムが実装可能であることを示しています。

- [紹介とCLIの使い方](/docs/algorithms/Nezha/manual.md) (英語)
- [アルゴリズム概要](/docs/algorithms/Nezha/algorithm_ja.md)
- [アルゴリズム詳細](/docs/algorithms/Nezha/algorithm_ja.md#nezha固有のノード)
- [fuzzufでの実装](/docs/algorithms/Nezha/algorithm_ja.md#fuzzufにおける実装)

## ライセンス

fuzzufはAGPL v3.0 (GNU Affero General Public License v3.0) で提供されます。いくつかの外部のプロジェクトに由来するコードは派生元のライセンスで提供されます。詳しくは[LICENSE](/LICENSE)を参照してください。

## 謝辞

本プロジェクトは、防衛装備庁が実施する、令和二年度安全保障技術研究推進制度JPJ004596による支援を受けて進められたものです。

