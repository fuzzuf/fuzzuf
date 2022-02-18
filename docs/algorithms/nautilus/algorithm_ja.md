# Nautilus
このドキュメントではfuzzufのNautilusモードについてと、その使い方を説明します。

## 1. Nautilusについて
Nautilus[^1]は2019年に発表された[オープンソース](https://github.com/nautilus-fuzz/nautilus/)の文法ベースファザーです。Nautilusは、入力テストケースの代わりに文法の定義を入力として与えることで、その文法に従ったテストケースを自動的に生成できる生成的なファザーに分類されます。また、Nautilusは検査対象のカバレッジを指標にテストケースを生成します。

AFLなどの一般的なファザーは、テストケースをバイトやビット単位でミューテーションします。したがって、プログラミング言語のインタプリタなどの特定の文法に従った正しい入力のみを受け付けるプログラムのファジングでは、文法的に誤ったテストケースを大量に生成してしまい、テストケースあたりに探索できるカバレッジが大幅に下がります。

このような問題を解決するため、文法に従った入力を生成できるファザーが開発されています。中でもWebブラウザで利用されているJavaScriptは攻撃対象となりやすいため、JavaScriptエンジンに対するファザーに主眼が置かれてきました。一方で、Nautilusはユーザーが定義した文法を解釈し、その文法に従った入力を生成できる汎用的な文法ベースのファザーです。

## 2. CLIでの使用方法
Nautilusモードを利用するには、fuzzuf本体をビルドする必要があります。fuzzufのビルド方法については[こちらのドキュメント](../../building.md)を参照してください。

### 2-1. 文法ファイルの用意
Nautilusはユーザーが定義した文法に従ったテストケースを生成します。
文法は[BNF記法](https://ja.wikipedia.org/wiki/%E3%83%90%E3%83%83%E3%82%AB%E3%82%B9%E3%83%BB%E3%83%8A%E3%82%A6%E3%82%A2%E8%A8%98%E6%B3%95)で記述する必要があります。例えば例として整数の算術演算をBNF記法で表してみましょう。
```
<EXPRESSION> ::= <TERM>
                 | <EXPRESSION> + <EXPRESSION>
                 | <EXPRESSION> - <EXPRESSION>
<TERM> ::= <FACTOR>
           | <FACTOR> * <FACTOR>
           | <FACTOR> / <FACTOR>
<FACTOR> ::= <NUMBER>
             | (<EXPRESSION>)
<NUMBER> ::= <DIGITS>
             | <SIGN><NUMBER>
             | <DIGITS><NUMBER>
<SIGN> ::= + | -
<DIGITS> ::= 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9
```
`<EXPRESSION>`や`<SIGN>`のように角括弧`< >`で囲まれたシンボルを**非終端記号**、`+`や`1`のように具体的なリテラルを表す文字を**終端記号**と呼びます。
Nautilusでこの文法を利用するには、文法を次のようにJSON形式の配列で定義する必要があります。
```json
[
    ["EXPRESSION", "{TERM}"],
    ["EXPRESSION", "{EXPRESSION}+{EXPRESSION}"],
    ["EXPRESSION", "{EXPRESSION}-{EXPRESSION}"],
    ["TERM", "{FACTOR}"],
    ["TERM", "{FACTOR}*{FACTOR}"],
    ["TERM", "{FACTOR}/{FACTOR}"],
    ["FACTOR", "{NUMBER}"],
    ["FACTOR", "({EXPRESSION})"],
    ["NUMBER", "{DIGITS}"],
    ["NUMBER", "{SIGN}{NUMBER}"],
    ["NUMBER", "{DIGITS}{NUMBER}"],
    ["SIGN", "+"],
    ["SIGN", "-"],
    ["DIGITS", "0"],
    ["DIGITS", "1"],
    ["DIGITS", "2"],
    ["DIGITS", "3"],
    ["DIGITS", "4"],
    ["DIGITS", "5"],
    ["DIGITS", "6"],
    ["DIGITS", "7"],
    ["DIGITS", "8"],
    ["DIGITS", "9"]
]
```
配列の各要素は非終端記号の定義にあたります。各要素は2つの文字列データを持ち、1つ目が非終端記号の識別子、2つ目がその非終端記号の定義（expression）にあたります。定義中に現れる非終端記号は波括弧`{ }`で囲う必要があります。**非終端記号の識別子は必ず大文字で始める必要があります。**
終端記号`{`および`}`で囲まれる部分が存在する場合、非終端記号と区別するために特殊記号としてエスケープする必要があります。このパターンが含まれる場合、例えば次のように記述してください。
```json
[
    ["BLOCK", "\\{ {STATEMENT} \\}"],
    ...
]
```

### 2-2. 文法ファイルのテスト
文法が複雑になると、定義した文法が正しいか確認したくなるでしょう。
`tools/nautilus/generator`に、文法ファイルからランダムなテストケースを生成できるプログラムがあります。例えば先程のファイルを与えると、文法が正しい場合は次のようにランダムな文字列が生成されます。
```
$ tools/nautilus/generator -g ./calc_grammar.json -t 100
4/(((4)+1+7+7+5*4+1)-2-6+2-48-9*+5+52-6)
$ tools/nautilus/generator -g ./calc_grammar.json -t 100
45-((2))+8*-+9+2/4+7+4-(((3-6)/5)-2*9+(3)-7)
```
詳しい使い方は`--help`オプションでも確認できますが、次のオプションが使えます。

- `--grammar_path` / `-g`: 文法ファイルのパス【必須】
- `--tree_depth` / `-t`: 木の最大サイズ（値が大きいほど長い出力が生まれる）【必須】
- `--number_of_trees` / `-n`: 生成するテストケースの個数【デフォルト:1】
- `--store` / `-s`: 生成したテストケースを保存するフォルダのパス【デフォルト:なし】

もし文法ファイルが誤っている場合はエラーが出力されます。まず、JSONが間違っている場合は次のようなエラーメッセージが表示されます。
```
[-] Cannot parse grammar file
[json.exception.parse_error.101] parse error at line 3, column 5: syntax error while parsing array - unexpected '['; expected ']'
```
この場合、文法ファイルの3行目のJSONの構文が間違っています。

また、次のようなエラーが発生する場合もあります。
```
Found unproductive rules: (missing base/non recursive case?)
START => EXPRESSION
EXPRESSION => TERM
EXPRESSION => EXPRESSION, +, EXPRESSION
EXPRESSION => EXPRESSION, -, EXPRESSION
TERM => FACTOR
TERM => FACTOR, *, FACTOR
TERM => FACTOR, /, FACTOR
FACTOR => NUMBER
FACTOR => (, EXPRESSION, )
NUMBER => FACTOR
terminate called after throwing an instance of 'exceptions::fuzzuf_runtime_error'
  what():  Broken grammar
```
これは終端に到達しない定義がある場合に出力されます。この例では`NUMBER => FACTOR`となっていますが、`FACTOR`を辿っても終端記号に到達しないため循環定義となり、エラーが出力されています。
このエラーは（タイプミスなどで）存在しない非終端記号の名前を使っている場合にも出力されます。

他にも次のようなエラーメッセージが出力されます。

- `Invalid rules (Rule must be array)`: 文法ファイルのJSONが配列形式でない。
- `Invalid rule (Each rule must be a pair of string)`: 非終端記号の定義のいずれかが文字列のペアとして表記されていない。（誤った箇所のJSONが表示されます。）
- `Could not interpret Nonterminal {...}. Nonterminal Descriptions need to match start with a capital letter and con only contain [a-zA-Z_-0-9]`: 非終端記号が大文字で始まっていない。あるいは使えない記号が含まれている。

また、次のように非終端記号の括弧を忘れても終端記号として認識されてエラーは発生しないため注意してください。（しかし、ジェネレータで生成されたテストケースを見ればすぐに気づくでしょう。）
```
["EXPRESSION", "{EXPRESSION}+{EXPRESSION"]
```

### 2-3. ファジング
例として



## 3. アルゴリズム概要

### 3-1. 文法の解釈


## 4. オリジナル実装との差分

### 4-1. ScriptRuleとRegexpRule


### 4-2. ASAN


## 5. 参考文献

[^1]: Aschermann, Cornelius et al. “NAUTILUS: Fishing for Deep Bugs with Grammars.” Proceedings 2019 Network and Distributed System Security Symposium (2019): n. pag.
