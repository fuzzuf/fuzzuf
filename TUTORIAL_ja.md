# チュートリアル

## ファザーコレクションとしてのfuzzufの使い方

ここでは、ファザーコレクションとしてのfuzzufを、どのように使えばよいかを段階的に説明します。
ファザー構築フレームワークとしてのfuzzufの使い方は、別のドキュメントを参照してください。

## ビルド要件

* [gcc](https://gcc.gnu.org/) バージョン7以上
  * バージョン8以上を推奨
  * 静的解析にはバージョン10以上が必要
* [CMake](https://cmake.org/) バージョン3.10以上
* [Boost C++ library](https://www.boost.org/) バージョン1.53.0以上
* [CPython](https://www.python.org/) バージョン3.0以上
  * (optional) VUzzerの利用にはバージョン3.7以上が必要
* [pybind11](https://pybind11.readthedocs.io/en/stable/) バージョン2.2以上
* [Nlohmann JSON](https://json.nlohmann.me/) バージョン2.1.1以上
* [Crypto\+\+](https://www.cryptopp.com/)
* (optional) [Doxgen](https://www.doxygen.nl/index.html)
* (optional) [Graphviz](https://graphviz.org/)
* (optional) [Mscgen](https://www.mcternan.me.uk/mscgen/)
* (optional) [Dia Diagram Editor](https://sourceforge.net/projects/dia-installer/)
* (optional) [Intel Pin](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html) [3.7](https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz)
### ビルド方法

推奨環境: Ubuntu 20.04（あるいは18.04）

まずはUbuntu 20.04を例に、fuzzufのビルド手順を示します。

```shell
$ sudo apt update
$ sudo apt install -y \
  build-essential cmake git libboost-all-dev \
  python3 nlohmann-json3-dev pybind11-dev libcrypto++-dev
$ git clone https://github.com/fuzzuf/fuzzuf.git
$ cd fuzzuf
$ cmake -B build -DCMAKE_BUILD_TYPE=Release # デバッグログを出力する場合はDebugに変更
$ cmake --build build -j$(nproc)
```

Ubuntu 18.04の場合、代わりに以下のコマンドを実行してビルドしてください。  

```shell
$ sudo apt update
$ sudo apt install -y \
  build-essential cmake git libboost-all-dev \
  python3 nlohmann-json-dev pybind11-dev libcrypto++-dev
$ git clone https://github.com/fuzzuf/fuzzuf.git
$ mkdir fuzzuf/build
$ cd $_
$ cmake ../ -DCMAKE_BUILD_TYPE=Release # 古い形式のコマンドなのは、aptでインストールされるCMakeのバージョンが古いため
$ make -j$(nproc)
```

### ファザーの使い方

このセクションでは、[docs/resources/exifutil](/docs/resources/exifutil)ディレクトリ以下に配置された、JPEGファイルからexif情報をパースするプログラム`exifutil`に対して、ファジングを行います。
ファジングを行うためには、プログラムのコンパイル時に計装を呼ばれる作業が必要です。このために、追加でaptから`afl++-clang`または`afl-clang`パッケージをインストールする必要があります。

以下のコマンドで計装用コンパイララッパーをインストールし、プログラムを計装ビルドします。

```shell
$ # afl++-clangはUbuntu 20.04+でのみ利用可能
$ # それ以下のUbuntuバージョンでは、代わりにafl-clangをインストール
$ # 両パッケージともに、afl-clang-fastがインストールされます
$ sudo apt install -y afl++-clang
$ pushd docs/resources/exifutil
$ CC=afl-clang-fast make
$ popd
```

次に、ファジングに使う初期シードを準備します。初期シードはPUT（Program Under Test: ファジング対象のプログラム）の、ミューテーションを適用する前の、最初のテストケースとして使用されます。今回のPUTはJPEGパーサーであるため、[docs/resources/exifutil/fuzz_input/jpeg.jpg](/docs/resources/exifutil/fuzz_input/jpeg.jpg)など適当なJPEGファイルを用意します。
これで、ファジングのための準備が整いました。次のコマンドで、AFLを使ったファジングを行います。

```shell
$ mkdir /tmp/input # 初期シードのためのディレクトリを作成
$ cp /path/to/jpeg/image.jpg /tmp/input
$ cd /path/to/fuzzuf/build
$ ./fuzzuf afl --in_dir=/tmp/input \
  --out_dir=/tmp/afl.out -- \
  ../docs/resources/exifutil/exifutil -f @@
```

最後のコマンドの`-f`オプションは、PUT固有のものであり、`fuzzuf`のオプションではないことに留意してください。

上記のコマンドを実行すると、ターミナルに以下のようなユーザーインターフェースが表示され、AFLによるファジングが開始します。

![fuzzuf-afl-exifutil](/docs/resources/img/fuzzuf-afl-exifutil.png)

このとき、PUTはファザーにより様々な入力を与えられながら繰り返し実行されており、その実行結果がクラッシュ、またはハングするようなら、その入力は保存されます。  
具体的にはPUTをクラッシュさせる入力が発見され、それ以前に保存されたものと重複しないと判断されると、その入力は`--out_dir`オプションで示されたディレクトリ以下の、`crashes`ディレクトリに保存され、上記UIの右上にある`unique crashes`の数値が1増加します。  
ファジングを終了するには、`Ctrl-C`で`fuzzuf`プロセスに対して`SIGINT`を送ります。`--out_dir`ディレクトリ以下の、クラッシュやハングを引き起こした入力を確認し、その原因を分析しましょう。

### 使用するファザーの変更

fuzzufで利用できるファザーは、AFLだけではありません。次は、AFLFastを使って、同じテスト用バイナリをファジングします。AFLFastがどのようなファザーかについては、[AFLFastのドキュメント](/docs/algorithms/aflfast/algorithm_ja.md)を参照してください。
使用するファザーを変更するには、fuzzufのコマンドライン引数（およびそれに伴うオプション）を変えるだけです。先ほどのコマンドにおけるファザーの指定を、`afl`から`aflfast`に変えて実行してみましょう。

```shell
$ ./fuzzuf aflfast --in_dir=/tmp/input \
  --out_dir=/tmp/aflfast.out \
  ../docs/resources/exifutil/exifutil -f @@
```

![fuzzuf-aflfast-exifutil](/docs/resources/img/fuzzuf-aflfast-exifutil.png)

AFLFastで採用されているパワースケジューリングは、ファザーを長時間実行することで、そのパフォーマンスをオリジナルのAFLのものから上昇させます。詳しくは、上記で挙げたドキュメントをご参照ください。

そのほかのファザーを試したい場合、同様にコマンドライン引数とオプションを変更すれば可能です。ただし、使用するファザーによっては、バイナリに対して特殊な処理を施す必要がある点に留意してください。  
各ファザーの使い方については、[ドキュメントフォルダ](/docs/algorithms)を参考にしてください。

