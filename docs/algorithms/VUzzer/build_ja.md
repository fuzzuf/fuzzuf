# VUzzer ビルド手順

VUzzer には以下に示す追加の外部依存があります。

* Python 3.7以上
* Intel Pin 3.7
* fuzzuf/PolyTracker

本手順では上記依存の解決方法について解説したのち、VUzzerのビルド方法を解説します。

## Python

Polytrackerの動作のため、バージョン3.7以上のPythonが必要です。

Ubuntu 20.04の場合、aptを通してインストール可能な `python3` パッケージ（バージョン3.8）が利用可能です。次のIntel Pinの節に進んでください。

Ubuntu 18.04またはその他の環境の場合、aptからインストール可能なpython3のバージョンは3.6であり要件を満たしません。したがって、[pyenv](https://github.com/pyenv/pyenv) などを使ってバージョン3.7以上のPythonを別途インストールする必要があります。

以下は pyenv を使用する場合のインストール手順です。

```bash
### 予めPythonが必要とする依存関係をインストールします。詳しくは各環境のドキュメントを参照してください。
### https://github.com/pyenv/pyenv/wiki#suggested-build-environment

### pyenvをダウンロードし、パスを通します
curl https://pyenv.run | bash
export PATH="$HOME/.pyenv/bin:$PATH"
eval $(pyenv init --path)

### pyenv環境でPython 3.7をビルド＆インストールします
pyenv install 3.7.12
pyenv local 3.7.12
```

他のインストール方法を採用する場合、システムで認識されている `python3` がPython 3.7以上という要件を満たすようにセットアップをお願いします。

最後に、以下のようにお使いのシェルで `python3` のバージョンが3.7以上であることを確認できればOKです。
Intel Pinの節に進んでください。

```bash
$ python3 --version
Python 3.7.12
```

## Intel Pin

Intelの公式サイトからIntel Pin 3.7をダウンロードし、任意のディレクトリに展開してください。

```bash
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz
tar -zxvf pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz
```

手順は以上です。PolyTrackerの節に進んでください。

## PolyTracker

fuzzuf版VUzzerは、データフロー解析手段として [fuzzuf/polytracker](https://github.com/fuzzuf/polytracker) を採用します。

<details> 
<summary>（参考情報）Why PolyTracker?</summary>

参考実装とした [オリジナルのVUzzer](https://github.com/vusec/vuzzer64) はデータフロー解析として [libdft64](https://github.com/vusec/vuzzer64/tree/master/libdft64) を採用しています。われわれがlibdft64の代わりにPolyTrackerを採用する理由は、われわれがlibdft64のデータフロー解析の精度を評価した結果、Ubuntu 18.04や20.04ではVUzzerの再現に必要な解析精度が達成されないと結論したからです。

fuzzufが採用するPolyTrackerは、本家である [trailofbits/polytracker](https://github.com/trailofbits/polytracker) に改造を施したものです。改造は、libdft64のデータフロー解析をPolyTrackerで再現することを目的とします。
</details>

PolyTrackerのビルド＆インストールは [PolyTrackerのREADME](https://github.com/fuzzuf/polytracker/blob/feature/make-polytracker-libdft64-compatible/README.md) で案内されている手順を実施してください。

## fuzzuf

最後にfuzzufをビルドします。レポジトリをクローンしたディレクトリまで移動し以下のコマンドを実行すれば完了です。  
cmakeの `PIN_ROOT` パラメータにはIntel Pinの節で展開したIntel Pin 3.7のディレクトリを指定してください。

```bash
cd /path/to/fuzzuf/directory
### fuzzuf のルートディレクトリで実行
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DDEFAULT_RUNLEVEL=Debug -DPIN_ROOT=<Intel Pinを展開したディレクトリへのパス>
cd build
make
```
