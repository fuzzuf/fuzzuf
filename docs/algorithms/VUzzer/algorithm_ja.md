# VUzzer

## VUzzerとは
 
https://github.com/vusec/vuzzer64

VUzzerは、2017年にNDSSに投稿された論文[^ndss17]で提案、開発されたファザーです。VUzzerは自身の持つキューに保持されているシードを1つ以上選択し、それに改変を加えることで未知の実行パスを発見しようとする、ミューテーションベースドファザーと呼ばれる種のファザーです。

VUzzerの最大の特徴は、ソースコードや入力フォーマットといった事前知識を必要とせず、PUTのコントロールフローやデータフローを解析する事で構造を推測し、効率良く実行パスを発見しようとすることです。事前知識を使わないapplication-awareなファザーのパイオアニアとして多くの論文から参照されています。

## 準備

VUzzerを実行する前にまずはPUTに対してIDAPythonによる静的解析とPolyTrackerによる計装を行う必要があります。
fuzzuf、Intel Pin、PolyTrackerを[インストール](/docs/algorithms/VUzzer/build_ja.md)した状態で、以下を実行してください。

### ASLRの無効化

VUzzerはプログラム実行時、通過したBasic Blockアドレスの集合をカバレッジとして使用するためASLRを無効化する必要があります。

```bash
sudo sysctl -w kernel.randomize_va_space=0
```

### tmpfsのマウント

PolyTrackerはテイント解析を実行したら伝搬したテイント情報をデータベースに書き込みます。この処理は非常に高頻度に発生しI/O負荷が高いためtmpfsに
書き出すように変更します。そのためにまずは任意のディレクトリ(デフォルトのデータベース出力先は`/mnt/polytracker`)にtmpfsをマウントしてください。

```bash
sudo mkdir -p /mnt/polytracker
sudo mount -t tmpfs -o size=100m tmpfs /mnt/polytracker
```

### PolyTrackerによる計装

PolyTrackerを実行して計装されたバイナリをビルドします。

```bash
cd build
mkdir vuzzer_test
cp test/put_binaries/calc/calc.c ./vuzzer_test
cd vuzzer_test
polybuild --instrument-target -g -o instrumented.bin calc.c
```

`polybuild`によって`calc`にテイント解析用の命令を計装したバイナリ`instrumented.bin`が生成されます。

### IDAPythonによる静的解析

```bash
gcc -o calc calc.c
/path/to/idat64 -A -S../../tools/bbweight/bb-weight-ida.py calc
```

静的解析が完了すると2つの辞書ファイル`unique.dict`、`full.dict`およびPUTのControl Flow Graph (CFG)に重み付けしたファイル `weight` が生成されます。


上記全てのステップ実行後、`vuzzer_test`ディレクトリに以下が生成されていれば成功です。

```
calc
calc.c
full.dict
instrumented.bc
instrumented.bin
instrumented_instrumented.bc
instrumented_instrumented.o
unique.dict
weight
```

## CLI上での使用方法

準備が完了したら`vuzzer_test`ディレクトリ内で

```bash
../fuzzuf vuzzer --in_dir=../test/put_binaries/calc/seeds -- ./calc @@
```

でVUzzerを起動できます。`--indir`で指定するディレクトリには初期シードを**3つ以上**置いてください。

その他、指定可能なオプションは以下の通りです:

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
 - ローカルなオプション(VUzzerのみで有効)
   - `--full_dict=path/to/full.dict`
     - `bb-weight.py`が生成したフル辞書ファイルへのパスを指定します。この辞書ファイルにはPUTバイナリ内に存在する全てのマジックナンバーが記録されています。
     - このオプションが指定されない場合は、`./full.dict` が指定されます。
   - `--unique_dict=path/to/unique.dict`
     - `bb-weight.py`が生成したユニーク辞書ファイルへのパスを指定します。この辞書ファイルにはPUTバイナリ内に存在するマジックナンバーが重複を取り除いて記録されています。
     - このオプションが指定されない場合は、`./unique.dict` が指定されます。
   - `--weight=path/to/weight/file`
     - `bb-weight.py`が生成した重みファイルへのパスを指定します。このファイルにはPUTのContol Flow Graph (CFG)を解析し、各ノードごとに計算した評価値が記録されています。
     - このオプションが指定されない場合は、`./weight` が指定されます。
   - `--inst_bin=path/to/instrumented/bin`
     - `polybuild`でコンパイルし出力された実行バイナリへのパスを指定します。このバイナリはPUTにテイント解析用の命令が計装された物です。
     - このオプションが指定されない場合は、`./instrumented.bin` が指定されます。
   - `--taint_db=path/to/taint/db`
     - テイント情報が記録されるデータベースへのパスを指定します。
     - このオプションが指定されない場合は、`/mnt/polytracker/polytracker.db` が指定されます。
   - `--taint_out=path/to/taint/db`
     - テイント情報が記録されるファイルへのパスを指定します。このファイルはデータベースに記録されたテイント情報から、lea,cmp命令に関する物を抽出しパースした出力を記録したものです。
     - このオプションが指定されない場合は、`/tmp/taint.out` が指定されます。

## アルゴリズム概要

TODO: アルゴリズム概要を追加

## 参考文献

[^ndss17]: Sanjay Rawat, Vivek Jain, Ashish Kumar, Lucian Cojocar, Cristiano Giuffrida, and Herbert Bos. 2017. VUzzer: Application-aware Evolutionary Fuzzing. In the Network and Distribution System Security (NDSS’17).

