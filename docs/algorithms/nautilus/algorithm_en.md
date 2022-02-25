# Nautilus
This document explains about Nautilus mode of fuzzuf and its usage.

## 1. About Nautilus
Nautilus[^1] is an [open-sourced](https://github.com/nautilus-fuzz/nautilus/) grammar-based fuzzer published in 2019. Nautilus requires the definition of grammar as input instead of some seed test cases and can automatically generate test cases according to the grammar. This kind of fuzzer is classified to a generative fuzzer. In addition, Nautilus is a coverage guided fuzzer, which uses the coverage of the inspection target as an indicator to generate test cases.

Some common fuzzers, such as AFL, mutate test cases by units of bytes or bits. These fuzzers struggle with fuzzing programs that accepts only grammatically-correct inputs such as interpreters of programming languages because the common fuzzers generate tons of grammatically-wrong test cases and most of them result in waste.

To address this problem, researchers have developed grammar-based fuzzers which can generate grammatically-correct test cases. In particular, they focus on developing fuzzers for JavaScript engine as JavaScript, a language widely used by Web browsers, is a good attack surface.
However, Nautilus is a generic grammar-based fuzzer which interprets a grammar defined by the user and can generate test cases according to it.

Nautilus has the following features.

- Requires the source code of an application and the user-defined grammar
- Works without input corpus
- Takes advantage of coverage feedback

The user can define the grammar, which enables to fuzz a specific function of the application, e.g., by removing uninteresting parts of the grammar.

## 2. Usage on CLI
You have to build fuzzuf before using Nautilus mode. Please refer to [this document](../../building.md) for how to build fuzzuf.

### 2-1. Preparing Grammar File
Nautilus can generate test cases according to a grammar defined by the user.
You must write the grammar in [BNF form](https://en.wikipedia.org/wiki/Backus%E2%80%93Naur_form). Let's write a BNF form of the arithmetic calculation of integer.
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
The symbols enclosed by angle brackets `< >`, such as `<EXPRESSION>` or `<SIGN>`, are called **non-terminals** and the characters representing specific literals, such as `+` or `1`, are called **terminals**.
You have to define the grammar in JSON array to use it in Nautilus.
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
Each element of the array represents the definition for a non-terminal. The element has 2 string data: the first one is the non-terminal symbol and the second one is the definition (expression) for the non-terminal. You must enclose every non-terminal symbol in the expression by braces `{ }`. **The non-terminal symbol must start with a capital letter.**
If a part of an expression is enclose by terminal characters `{` and `}`, you must escape them as special symbols to distinguish with non-terminals. If the definition of a non-terminal includes the pattern, please write like the following, for example:
```json
[
    ["BLOCK", "\\{ {STATEMENT} \\}"],
    ...
]
```

### 2-2. Testing Grammar Files
You may want to check if your grammar is correct when it gets complicated.
`tools/nautilus/generator` is the program to generate some random test cases according to the grammar you define. If you give it the grammar we defined previously, a random string will be generated like the following if the grammar is correct.
```
$ tools/nautilus/generator -g ./calc_grammar.json -t 100
4/(((4)+1+7+7+5*4+1)-2-6+2-48-9*+5+52-6)
$ tools/nautilus/generator -g ./calc_grammar.json -t 100
45-((2))+8*-+9+2/4+7+4-(((3-6)/5)-2*9+(3)-7)
```
The following options are available, which you can also check by `--help` option.

- `--grammar_path` / `-g`: Path to the grammar file [**Required**]
- `--tree_depth` / `-t`: Maximum size of tree (The bigger this value is, the longer the output will be) [**Required**]
- `--number_of_trees` / `-n`: Number of test cases to generate [Default:1]
- `--store` / `-s`: Path to the folder to save generated test cases in [Default:None]

If your grammar file is invalid, it will dump an error. The following error message will be shown if JSON is invalid.
```
[-] Cannot parse grammar file
[json.exception.parse_error.101] parse error at line 3, column 5: syntax error while parsing array - unexpected '['; expected ']'
```
In this case, the 3rd line of the grammar file has invalid JSON format.

A longer error like the following may also happen.
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
This error occurs if a non-terminal cannot reach the terminal. In the example above, `NUMBER => FACTOR` is invalid because it cannot reach the terminal by traversing `FACTOR`, which is a infinite loop.
This error also shows up if an undefined non-terminal identifier (like typo) apperas.

You may encounter other errors like the following:

- `Invalid rules (Rule must be array)`: The grammar is not a JSON array.
- `Invalid rule (Each rule must be a pair of string)`: Any of the non-terminal definition is not represented as a pair of strings. (This error will also show the invalid part of the JSON.)
- `Could not interpret Nonterminal {...}. Nonterminal Descriptions need to match start with a capital letter and can only contain [a-zA-Z_-0-9]`: A non-terminal identifier does not start with a capital letter, or contains invalid characters.

Also, be careful that no error will happen if you forget to write brace for a non-terminal because it can be recognized as terminal characters. (Although, you will be able to find the error immediately by checking the test cases generated.)
```
["EXPRESSION", "{EXPRESSION}+{EXPRESSION"]
```

### 2-3. Fuzzing
Let's fuzz a calculator using the grammar we have written so far.
At `test/put_binaries/nautilus/calc`, there exists a calculator instrumented by afl-gcc. This calculator prints the result of arithmetic calculation but it causes a crash when the result becomes a multiple of 314 except zero.
```c
int res = express();
if (res != 0 && res % 314 == 0) crash();
```
You have to instrument the target binary by AFL in Nautilus mode.

The Nautilus mode of fuzzuf provides the following options:

- `--out_dir`, `-o`: Path to folder to save the fuzzing result [**Required**]
- `--exec_timelimit_ms`: Time limit of an execution (ms) [Default: 1000]
- `--exec_memlimit`: Memory limit of the target binary (MB) [Default: 25]
- `--grammar`: Path to grammar file [**Required**]
- `--bitmap-size`: Bitmap size [Default: 1<<16]
- `--generate-num`: The number of test cases generated in one fuzz loop [Default: 100]
- `--detmut-num`: Number of cycles to execute deterministic mutations [Default: 1]
- `--max-tree-size`: Maximum size of generated tree [Default: 1000]
- `--no-forksrv`: Disable fork server mode (Not recommended)

You can fuzz the calculator like this, for example:
```
$ fuzzuf nautilus --out_dir output \
                  --grammar ./calc_grammar.json \
                  -- ./test/put_binaries/nautilus/calc @@
```
It is working successfully if a screen showing the status of fuzzing in real time appears.

If your usage or grammar file is wrong, an error will show up.

- `Grammar does not exist!`: Grammar file specified by `--grammar` does not exist.
- `Unknown grammar type ('.json' expected)`: The extension of grammar file is not ".json"
- `Cannot parse grammar file`: The content of grammar file is wrong. (Check your grammar file as explained in section 2-2.)

## 3. Algorithm
Generally, grammar based fuzzers generates AST (abstract syntax tree) according to a specific grammar and mutates a part of the AST to create testcases. Nautilus internally only uses the tree representation and mutates the tree.
In this section, we explain the design of how Nautilus generates and mutates the testcases.

### 3-1. Generation
Since a non-terminal may have multiple rules, we need an algorithm to decide which rule to pick up. Nautilus uses uniform generation algorithm.
Let's consider the following grammar:
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
For example, `<STMT>` has 2 rules: `return 1` or `<VAR> = <EXPR>`. If we choose a rule for each non-terminal by naive randomness, `return 1` is chosen with 50% probability. On the other hand, if we choose `<VAR> = <EXPR>`, `<EXPR>` has another 2 rules: `<NUMBER>` and `<EXPR> + <EXPR>`. The probability that one of them is chosen is 25% from `<STMT>`.
The deeper part of the tree is selected with less probability with a naive randomness like this, which results in generating similar testcases. Naitlus, on the other hand, uses an algorithm by McKenzie[^2] so that it can select every rule in the grammar with the same probability.

### 3-2. Minimization
Nautilus attempts to create a smaller testcase that triggers the same new coverage after it found an interesting input. Minimized inputs can make the execution time shorter and the number of set of potential mutations smaller. Nautilus uses two approaches to minimize the testcase that found new paths.

#### 3-2-a. Subtree Minimization
**Subtree Minimization** is a process to make the subtree of AST as short as possible.
We generate the smallest possible subtree for each non-terminal. Then, we replace the subtree of each node sequentially and check if we get the same coverage as that of the original tree. If we get the same coverage, the replace tree is taken and otherwise the change is discarded.

#### 3-2-b. Recursive Minimization
**Recursive Minimization** is a process executed after the subtree minimization.
This minimization replaces the nested part of AST. In the following figure, the statement `a = 1 + 2` is, for example, replaced into `a = 1`.
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

### 3-3. Mutation
After the minimization phase, Nautilus mutates the AST. Nautilus uses multiple mutation methods explained below.

#### 3-3-a. Random Mutation
**Random Mutation** picks a random node from AST and replaces it with a randomly-generated new subtree whose root node shares the same non-terminal as the original one. The size of the subtree to be generated is also random but the maximum value is configured by `--max-tree-size` option.

#### 3-3-b. Rules Mutation
**Rules Mutation** sequentially replaces each node of the AST with a new subtree generated by all other possible rules of the non-terminal. By replacing a node with a new rule, improvement of the coverage is expected as it uses a new grammar.

#### 3-3-c. Random Recursive Mutation
**Random Recursive Mutation** randomly selects a recursive subtree and repeats it 2 to the nth power times (1≦n≦15). This mutation can create trees with higher degrees of nexting.
The paper mentions 1≦n≦15 but the original Nautilus implementation uses 1≦n≦10 as the limit, so the fuzzuf also implements it with the latter bound.

#### 3-3-d. Splicing Mutation
**Splicing Mutation** replaces a subtree of the testcase with a subtree taken from another testcase that found different paths. That is, splicing mutation combined two testcases.


## 4. Difference From the Original Implementation
In this section, we explain some differences of the implementation between the Nautilus mode of fuzzuf and the original Nautilus.

### 4-1. ScriptRule and RegexpRule
The original Nautilus implementation makes it possible to use Python and regular expressions in addition to JSON in order to write a grammar. Since those features are not necessarily required to define a grammar but require some external dependencies, we decided not to support those features in the first release of Nautilus mode.

### 4-2. ASAN
The application does not send a signal on the vulnerability detection when it is compiled with address sanitizers. Nautilus also checks the feedback of the sanitizers to catch the vulnerabilities detected by ASAN.
However, the current Nautilus mode of fuzzuf does not support ASAN-instrumented program. This is because we're currently working on the revision of the Executors and so on. We will likely support sanitizers in the future releases.

### 4-3. AFL Mutations
In addition to the mutation methods mentioned in this documentation, the original paper explains a mutation method named **AFL Mutations**. However, this mutation method is not implemented even in the original Nautilus. Therefore, the current Nautilus mode of fuzzuf also does not support this feature.

----

[^1]: Aschermann, Cornelius et al. “NAUTILUS: Fishing for Deep Bugs with Grammars.” Proceedings 2019 Network and Distributed System Security Symposium (2019): n. pag.
[^2]: Bruce McKenzie. Generating strings at random from a context free grammar. 1997.
