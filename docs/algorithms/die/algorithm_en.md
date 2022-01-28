# DIE

## About DIE
[DIE](https://github.com/sslab-gatech/DIE/)[^die] is a fuzzer developed by [SSLab](https://gts3.org/) to find bugs in JavaScript engines. Generally speaking, there are several problems in fuzzing JavaScript engines:

- The fuzzer needs to generate syntactically correct JavaScript test cases.
- The fuzzer wants to generate JavaScript test cases that run without runtime errors.
  - Ordinal fuzzers enclose every statement with try-catch to avoid the scripts from stopping by runtime errors
  - However, the JIT compiler doesn't optimize functions including try-catch statement, which decreases the amount of bugs found in the JIT engine.

State-of-the-Art fuzzers such as [fuzzilli](https://github.com/googleprojectzero/fuzzilli) address these obstacles. DIE, as well as fuzzilli, does not only resolve the problems but also has a feature called aspect-preserving.

The intention of DIE is to give "finding bugs similar to the past bugs" priority. Therefore, it mutates JavaScript test cases with keeping its basic structure such as function calls or for-statements. In this way, DIE is likely to be able to preserve the "aspect" of the original test cases through the mutation process.

DIE mode is available on fuzzuf as an example implementation of a fuzzer to take advantages of an external mutation engine.

## Usage on CLI

### Requirements
DIE requires the following tools (Tested on Ubuntu 14.04/18.04/20.04):

- [Node.js](https://nodejs.org/en/download/) (Tested on 16.13 LTS at Jan 17th, 2022)
  - npm (6 or later is recommended)
  - node (10 or later is recommended)
- Python 3 (3.6 or later is recommended)

### Automated Setup
A bash script to setup DIE is available in fuzzuf. Run the following command after building fuzzuf to setup DIE.

```bash
cmake --build build --target die
```

If the following message shows up after running the command above, the installation is successful. Jump to the section "Preparing Seeds."
```
[+] DIE successfully setup!
```

### Manual Setup
If you don't choose to use the automated setup for some reason, follow the next steps to manually setup DIE.

First of all, clone DIE from the official repository. We've tested with the latest commit `f1ab180c18ea4096d6c3336a7dc3e00af897549d` at Jan 17th, 2022.
```bash
git clone https://github.com/sslab-gatech/DIE/
```

Then install the required packages.
```bash
cd DIE/fuzz/TS
npm install
```

You also need to transpile TypeScript into JavaScript.
```bash
node_module/.bin/tsc
```

Now you finished everything required to use DIE mode of fuzzuf.

### Preparing Seeds
DIE requires initial seeds to be mutated.
The seeds must be JavaScript files that have extension `.js` and one or more seeds are necessary. Because of the nature of DIE, it's desirable to use Proof-of-Concepts of the bugs found in the past as test cases.
The seed set used in the original paper of DIE is [published in GitHub](https://github.com/sslab-gatech/DIE-corpus).

The JavaScript files in the seed directory are instrumented before starting the fuzzing loop and the type information is collected. Those type infomation is saved to a file with the extension `.t`. If this file exists, fuzzuf skips to collect type information for the test case when fuzzing is rerun in the future. (Therefore, you need to delete the files with the extension `.t` if you change the contents of test cases in the seed directory.)

### Fuzzing with DIE
You can use DIE mode with the following command, for example:

```bash
fuzzuf die --in_dir=input --out_dir=output -- ./target/d8 @@
```

In the example above, `./target/d8` is the PUT to be fuzzed.
You must prepare one or more JavaScript files in the directory specified by `--in_dir`.  Also, you have to compile the target JavaScript engine to be fuzzed (PUT) by afl-gcc in advance.
Alternatively, there is a pre-compiled QuickJS executable available as a PUT [under `put_binaries` directory](/test/put_binaries/README.md#quickjsqjs).

You can use the same basic options as AFL but DIE mode also has some options.

- `--die_dir`: Path to cloned DIE directory (default: `tools/die/DIE`)
- `--typer`: Path to `tools/die/typer.py` (default: `tools/die/typer.py`)
- `--node`: Command to execute JavaScript (default: `node`)
- `--d8`: Path to d8 (If not specified, PUT is used)
- `--d8_flags`: Flags passed to JS engine specified by `--d8` (default: empty)
- `--mut_cnt`: Number of scripts to be generated in one mutation (default: 100)

## Overview of Algorithm
The fuzzing loop of DIE consists of "seed selection", "mutation", "execution", and "coverage feedback."
DIE instruments the seed test cases and executes them to dynamically collect the type of variables in the scripts, which will be used for mutation.

### Collecting Type Information
DIE is a mutational fuzzer that takes one or more JavaScript files as input and changes them through mutation. DIE collects type information of the input test case dynamically and use it to reduce the amount of runtime errors.
For example, consider the mutation of the following code:

```javascript
let s = "Hello World";
let v = s.split(" ");
```

If this code is mutated into the following one, a runtime error happens in the method call at the second line.

```javascript
let s = function(v) { return v; };
let v = s.split(" ");
```

To prevent this kind of invalid mutations, DIE holds type information for each variable. First, DIE adds the following instrumentation to output type information at all points after the object definition and the object usage in the input test case.

```javascript
console.log("loc:1,typeof(s):"+typeof(s));

console.log("loc:2,typeof(s):"+typeof(s));
console.log("loc:2,typeof(s.split):"+typeof(s.split));
let v = s.split(" ");
console.log("loc:2,typeof(v):"+typeof(v));
```

By executing the instrumented code, DIE dynamicaly collects type information for each variable in the script. Note that the reason why the type is checked everywhere, even for variables with the same name, is that JavaScript is a dynamically typed language.

### Mutation
DIE is designed to mutate only with variables of the same type as much as possible using the type information collected in advance. It also supports variables that can have multiple types in the same location depending on the execution, and object types with properties.

There are three main mutation strategies for DIE.

- Mutation with Typed AST
- Inserting new statements
- Creating new variables

All of them are executed in a way that does not destroy the structure of the script. The number of mutations and the probability of inserting a new statement are defined in `DIE/fuzz/TS/esfuzz.ts`.

### Coverage
The original DIE implementation collects coverage information in the same way as AFL. The code coverage of AFL uses a hit count of one byte for each edge. However, DIE does not use a hit count, but provides one bit of data for each edge, and only records whether or not it passed through the edge. This is because in JavaScript, for example, simply changing the loop counter will increase the hit count, and such a change is meaningless.
In fuzzuf, this refined coverage for JavaScript fuzzers is to be implemented in the future.

### Scheduling
DIE uses the same scheduling as AFL.

### Distributed Fuzzing
DIE can distribute the fuzzing process on multiple machines by communicating with redis server. The coverage information is also shared among all machines.
However, the current fuzzuf does not implement this feature.

## Reference

[^die]: S. Park, W. Xu, I. Yun, D. Jang and T. Kim, "Fuzzing JavaScript Engines with Aspect-preserving Mutation," 2020 IEEE Symposium on Security and Privacy (SP), 2020, pp. 1629-1642, doi: 10.1109/SP40000.2020.00067.
