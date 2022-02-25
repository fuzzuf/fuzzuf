# Nautilus
このドキュメントではfuzzufのNautilusモードについてと、その使い方を説明します。

## 1. Nautilusについて
Nautilus[^1]は2019年に発表された[オープンソース](https://github.com/nautilus-fuzz/nautilus/)の文法ベースファザーです。Nautilusは、入力テストケースの代わりに文法の定義を入力として与えることで、その文法に従ったテストケースを自動的に生成できる生成的なファザーに分類されます。また、Nautilusは検査対象のカバレッジを指標にテストケースを生成します。

AFLなどの一般的なファザーは、テストケースをバイトやビット単位でミューテーションします。したがって、プログラミング言語のインタプリタなどの特定の文法に従った正しい入力のみを受け付けるプログラムのファジングでは、文法的に誤ったテストケースを大量に生成してしまい、テストケースあたりに探索できるカバレッジが大幅に下がります。

このような問題を解決するため、文法に従った入力を生成できるファザーが開発されています。中でもWebブラウザで利用されているJavaScriptは攻撃対象となりやすいため、JavaScriptエンジンに対するファザーに主眼が置かれてきました。一方で、Nautilusはユーザーが定義した文法を解釈し、その文法に従った入力を生成できる汎用的な文法ベースのファザーです。

Nautilusは以下のような特徴を持ちます。

- 検査対象のソースコードと、事前に定義した文法が必要
- 入力テストケースが不要
- フィードバックのカバレッジを利用

ユーザーが文法を定義できるため、文法中の不要な部分を削除することで、検査したい機能に絞ったファジングも可能です。

## 2. CLIでの使用方法
Nautilusモードを利用するには、fuzzuf本体をビルドする必要があります。fuzzufのビルド方法については[こちらのドキュメント](../../building.md)を参照してください。

### 2-1. 文法ファイルの用意
Nautilusはユーザーが定義した文法に従ったテストケースを生成します。
文法は[BNF記法](https://ja.wikipedia.org/wiki/%E3%83%90%E3%83%83%E3%82%AB%E3%82%B9%E3%83%BB%E3%83%8A%E3%82%A6%E3%82%A2%E8%A8%98%E6%B3%95)で記述する必要があります。

#### 2-1-a. 基本的な書き方
例えば例として整数の算術演算をBNF記法で表してみましょう。
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
Nautilusでこの文法を利用するには、文法を例えば次のようにJSON形式の配列で定義する必要があります。
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

#### 2-1-b. 複数ルールの統合
先の例ではBNF記法における`|`（「または」を表す記号）を複数のルールに分割しました。しかし、これではルールが煩雑になってしまうため、fuzzufのNautilusモードでは次のような記法にも対応しています。
```json
["DIGITS", ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]]
```
これは非終端記号を右辺に含む場合でも利用できます。
```json
["EXPRESSION", [
  "{TERM}",
  "{EXPRESSION}+{EXPRESSION}",
  "{EXPRESSION}-{EXPRESSION}"
]]
```

#### 2-1-c. バイナリデータ
Nautilusモードは電卓やインタプリタといった人間が読める形式の入力だけでなく、PDFのような決まった形式を持つバイナリファイルの生成にも利用できます。このようなときASCII文字以外のバイナリデータを文法に含める必要がありますが、JSON形式はバイナリデータをサポートしていません。
そこで、fuzzufのNautilusモードでは次のように、配列形式でバイナリデータの終端記号を表記できます。
```json
["NULL", [0]]
```
次のようにバイナリデータ列も表せます。（残念ながらJSONは10進数表記しかサポートしていません。）
```json
["DEADBEEF", [239, 190, 173, 222]]
```
また、バイナリデータ列中に文字列が含まれる場合、それらを結合したルールとして認識されます。例えば以下のルールの場合、`A`という非終端記号は`\x00A\x00BBBB\xFFA\xFF`に展開されるでしょう。
```json
["A", [0, "A{B}A", 255]],
["B", [0, "BBBB", 255]],
```

複数のルールを`|`記号で統合するときにもバイナリデータを使用できます。つまり、
```json
["A", ["hello", [0], ["bye", 128]]]
```
は
```json
["A", "hello"],
["A", [0]],
["A", ["bye", 128]]
```
と等価です。

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
- `Could not interpret Nonterminal {...}. Nonterminal Descriptions need to match start with a capital letter and can only contain [a-zA-Z_-0-9]`: 非終端記号が大文字で始まっていない。あるいは使えない記号が含まれている。

また、次のように非終端記号の括弧を忘れても終端記号として認識されてエラーは発生しないため注意してください。（しかし、ジェネレータで生成されたテストケースを見ればすぐに気づくでしょう。）
```
["EXPRESSION", "{EXPRESSION}+{EXPRESSION"]
```

### 2-3. ファジング
これまで使ってきた文法を使って電卓プログラムをファジングしてみましょう。
`test/put_binaries/nautilus/calc`にafl-gccで計装された電卓プログラムがあります。この電卓は算術演算を計算して結果を出力してくれますが、計算結果が0でない314の倍数になったときにクラッシュを発生してしまいます。
```c
int res = express();
if (res != 0 && res % 314 == 0) crash();
```
Nautilusモードでは、検査対象をあらかじめAFLで計装しておく必要があります。

fuzzufのNautilusモードは次のオプションが提供されています。

- `--out_dir`, `-o`: ファジング結果を出力するフォルダパス【必須】
- `--exec_timelimit_ms`: 検査対象の1回あたりの実行時間の上限（ミリ秒）【デフォルト: 1000】
- `--exec_memlimit`: メモリ使用量の上限（MB）【デフォルト: 25】
- `--grammar`: 文法ファイルのパス【必須】
- `--bitmap-size`: ビットマップサイズ【デフォルト: 1<<16】
- `--generate-num`: ファジングループの一回で生成されるテストケースの数【デフォルト: 100】
- `--detmut-num`: 決定的ミューテーションを実行するサイクル数【デフォルト: 1】
- `--max-tree-size`: 生成される木の最大サイズ【デフォルト: 1000】
- `--forksrv`: Fork Serverモードの有効・無効【デフォルト: 有効】（無効化は非推奨）

例えば次のようにして電卓プログラムをファジングできます。
```
$ fuzzuf nautilus --out_dir=output \
                  --grammar=./calc_grammar.json \
                  -- ./test/put_binaries/nautilus/calc @@
```
Fuzzingの結果をリアルタイムで反映させた画面が表示されれば成功です。

オプションや文法ファイルを間違えると次のようなエラーが表示されます。

- `Grammar does not exist!`: `--grammar`で指定された文法ファイルが存在しない。
- `Unknown grammar type ('.json' expected)`: 文法ファイルの拡張子が".json"でない。
- `Cannot parse grammar file`: 文法ファイルの内容が誤っている。（2-2節のジェネレータを利用して文法ファイルを確認してください。）

## 3. アルゴリズム概要
文法ベースファザーは一般的に、特定の文法に従って構文木を生成したり、また構文木の一部をミューテーションしたりといった手法でテストケースを作成します。Nautilusもファジングの過程ではテストケースを木構造として保持しており、それに対してミューテーションなどを実行します。
この節では、テストケースの生成やミューテーションに関するNautilusの設計について説明します。

### 3-1. テストケースの生成
１つの非終端記号が複数のルールを持つ場合があるため、どのルールを使うかを決めるアルゴリズムが必要になります。Nautilusでは、一様生成（uniform generation）というアルゴリズムを利用しています。
例えば次の文法を例に考えましょう。
```
<PROG> := <STMT>
<PROG> := <STMT>; <PROG>
<STMT> := return 1
<STMT> := <VAR> = <EXPR>
<VAR>  := a
<EXPR> := <NUMBER>
<EXPR> := <EXPR> + <EXPR>
<NUMBER> := 1
<NUMBER> := 2
```
例えば`<STMT>`に対しては`return 1`あるいは`<VAR> = <EXPR>`の2種類のルールがあります。もし各非終端記号に対してどのルールを選ぶかを単純なランダムで選択した場合、50%の確率で終端の`return 1`が選ばれます。一方、`<VAR> = <EXPR>`が選ばれた場合はさらに`<EXPR>`で複数のルールが登場します。`<EXPR>`に対しては`<NUMBER>`と`<EXPR> + <EXPR>`の2つのルールがありますが、`<STMT>`から見た時、それぞれが選ばれる確率は25%になります。
このように、単純なランダムでは木の深い部分ほど選ばれる確率が下がってしまい、結果として同じようなテストケースばかりを生成してしまいます。そこで、NautilusではMcKenzie[^2]により提案されたアルゴリズムを用いて、文法のすべてのルールが一様な確率で選ばれるように設計しています。

### 3-2. 最小化
興味のある入力が見つかったら、Nautilusはその入力と同じカバレッジを得られるより小さい入力を生成しようとします。この最小化によりテストケースを小さくすることで、実行時間が短くなったり、ミューテーションで選択できるノードの幅が狭まったりという利点があります。Nautilusでは新しいパスに到達したテストケースを最小化するために2つの手法を用いています。

#### 3-2-a. 部分木最小化
部分木最小化(**Subtree Minimization**)は、構文木の部分木をなるべく短くする処理です。
まず、各非終端記号に対して最も小さい部分木を生成します。そして、各ノードの部分木を順番に置き換え、元の木と同じカバレッジが得られるかを確認します。もし同じカバレッジが得られれば置換後の木が採用され、そうでなければ変更は破棄されます。

#### 3-2-b. 再帰的最小化
再帰的最小化(**Recursive Minimization**)は部分木最小化の後に実行されます。
この処理では構文木中のネストした部分を置き換えます。次のように`a = 1 + 2`という文が、例えば`a = 1`に置換されます。
```
   PROG                  PROG
    |                     |
   STMT                  STMT
  / |  \                / |  \
VAR = EXPR            VAR = EXPR
 |    / | \     ---->  |     |
 a EXPR + EXPR         a    NUM
    |      |                 |
   NUM    NUM                1
    |      |
    1      2
```

### 3-3. ミューテーション
テストケースの最小化が終わったら、構文木のミューテーションを開始します。Nautilusでは複数のミューテーション手法が使われます。

#### 3-3-a. ランダムミューテーション
ランダムミューテーション(**Random Mutation**)では、構文木中のノードをランダムに1つ選択し、その非終端記号をルートとして新たに生成したランダムな部分木で置き換えます。この際生成される部分木のサイズはランダムですが、最大値は`--max-tree-size`で設定できる値に依存します。

#### 3-3-b. ルールミューテーション
ルールミューテーション(**Rules Mutation**)では、構文木中の各ノードについて、その非終端記号から生成できる他のルールを利用して作った部分木に置き換えます。使われていないルールで置き換えることにより、これまで現れなかった文法を利用するためカバレッジの向上が見込めます。

#### 3-3-c. ランダム再帰ミューテーション
ランダム再帰ミューテーション(**Random Recursive Mutation**)では、ネストした部分木をランダムに選び、そのネストを2のn乗回(1≦n≦15)回繰り返します。これにより、高次数のネストを持つ構文木が生成できます。
論文ではnの最大値は1≦n≦15となっていますが、オリジナルのNautilusの実装では1≦n≦10となっているため、fuzzufでも後者の実装を採用しています。

#### 3-3-d. スプライスミューテーション
スプライスミューテーション(**Splicing Mutation**)では、テストケースの部分木を、異なるパスを発見した別のテストケースの部分木で置き換えます。つまり、2つのテストケースを組み合わせるミューテーションになります。

## 4. オリジナル実装との差分
この節では、fuzzufのNautilusモードと、オリジナルのNautilusの実装における違いについて説明します。

### 4-1. ScriptRuleとRegexpRule
オリジナルのNautilusの実装では、単純なJSONだけでなく、Pythonと正規表現を使って文法を定義できます。これらの機能は文法を定義するのに必ずしも必要ではなく、一方で外部依存を増やしてしまうため、Nautilusモードの最初のリリースではサポートしていません。

### 4-2. ASAN
アドレスサニタイザ(ASAN)を付けてコンパイルされたアプリケーションは脆弱性を検知した際にシグナルを発生しません。Nautilusはサニタイザからのフィードバックも確認しており、ASANによる脆弱性検知も補足できます。
しかし、現在のfuzzufのNautilusモードはASANで計装されたプログラムをサポートしていません。これは、我々が現在Executorなどの機能を改良しているためです。将来のリリースでサニタイザもサポートされる予定です。

### 4-3. AFL Mutations
このドキュメントで説明したミューテーション手法の他に、元論文では**AFL Mutations**というミューテーション手法が説明されています。しかし、このミューテーション手法はオリジナルのNautilusでも実装されていません。そのため、現在のfuzzufのNautilusモードでもこの機能は実装していません。

----

[^1]: Aschermann, Cornelius et al. “NAUTILUS: Fishing for Deep Bugs with Grammars.” Proceedings 2019 Network and Distributed System Security Symposium (2019): n. pag.
[^2]: Bruce McKenzie. Generating strings at random from a context free grammar. 1997.
