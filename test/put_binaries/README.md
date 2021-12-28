# テストで使用するPUTの生バイナリの配置場所

このディレクトリにおかれているバイナリファイル群は、PUT側にinstrumentが導入されていることを前提としているテストにおいて用いられるPUTである。
当初、これらのPUTは、サブディレクトリtest/instrument/以下のテストでのみ使用する予定だったが、fork server modeの追加によって、他のサブディレクトリのテストにおいても使用することが望ましくなったためここに配置している。

このディレクトリにあるバイナリのうち、command\_wrapperはAFL\+\+で、
それ以外のものは 2021/4/19 16:33現在のfeature/fork-server-modeブランチのwyvern-clang++で
`-O0 -g -static -flto`
でビルドされている。

理想的にはこれらのPUTもテストのビルド時に生成したいところだが、
そもそもwyvern-clangが使用できる環境でしかテストが実行できなくなる上、
依存するwyvern-clangのブランチ・バージョン等を統一または指定する簡便な手立てが
思いつかないので、当座の処置として直にファイルを配置することとしている。
当然、結果的にこれらのPUTを用いたテストは一般的なLinuxの環境でしか動かない。
PUTを更新する際は、このREADME中の上記の時刻・ブランチ等を編集した上で、すべてのPUTを漏れなく更新すること。

以下、各バイナリの説明:

## zeroone
test/instrument以下のREADMEに記載があるため、そちらを参照。

## command\_wrapper
これまで、test/fuzzer以下などでFuzzerインスタンスを生成したテストを行う際は、"/bin/cat"などを対象のPUTとしていた。
当然"/bin/cat"は、wyvern-clangによるinstrumentが挿入されていないが、これによって生じる不具合は「共有メモリにcoverageが書き込まれない」という1点のみで、fork&execが正しく実行できているか、生成したシードをPUTに読み込めているか等の確認においては特別支障がなかった。
しかしながら、fork server modeが導入されたことにより、fork server modeで動作しているWyvernをテストする場合はinstrumentが必須となってしまった（PUT側にfork serverが存在することを暗黙の内に前提としているため）。
したがって、「instrumentを挿入したプログラムが、内部でexecv関数を利用して"/bin/cat"を呼び出す」という形のwrapperを噛ませることで対処することとした。
このwrapperに相当するのがcommand\_wrapperである。
ソースコードはこのディレクトリのcommand\_wrapper.cpp。
