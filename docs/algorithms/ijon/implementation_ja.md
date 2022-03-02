# fuzzufにおけるIJONの実装

## 参考にしたオリジナルのIJONの実装

- バージョン: 2.51b-ijon
- コミット:   https://github.com/RUB-SysSec/ijon/commit/56ebfe34709dd93f5da7871624ce6eadacc3ae4c

## オリジナルの実装との差分

バグなどによって意図しない差異が発生していない限り、オリジナルのファザーを完全に再現しており、差分はありません。
ただし、fuzzuf上のAFLが実装していない、オリジナルのAFLの機能については、当然IJONにおいても使用できません。

## 重要なTo-Do: アノテーションの実装

注意しなければならないこととして、現在のfuzzufではIJONの主要なコンポーネントであるはずのアノテーションが実装されていません。
これは、fuzzufがまだ独自の計装ツールを持っていないことに起因しており、計装ツールが準備され次第、実装に取り掛かる予定です。
その他のTo-Doについては、[TODO.md](https://github.com/fuzzuf/fuzzuf/blob/master/TODO.md)を確認してください。

## 追加されているHierarFlowルーチン

- SelectSeed: IJONのシードキューからシードを選択する。
- PrintAflIsSelected: 20%の確率でAFLのコードフローが選択された場合に、AFLが選択された旨を出力する。
- MaxHavoc: 80%の確率でIJONのコードフローが選択された場合に開始するミューテーション。
- UpdateMax: IJONのシードキューを更新する処理。
