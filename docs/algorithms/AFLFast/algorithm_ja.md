# AFLFast

## AFLFastとは

[AFLFast](https://github.com/mboehme/aflfast)[^ccs16]は、Michał Zalewskiによって開発された[AFL](https://github.com/google/AFL)を拡張したファザーです。本稿で触れないAFLの基本的なアルゴリズムについては[AFL/algorithm_ja.md](/docs/algorithms/AFL/algorithm_ja.md)を参照してください。
AFLFastを開発したMarcel Böhmeのチームは、AFLがあるシードから生成した入力のほとんどが同じパスを通り、興味深い挙動を示す他のパスはあまり通らないことを発見しました。これらの挙動を改善することによって、脆弱性に起因したバグを引き起こす入力をAFLのおよそ7倍高速に発見できるようになりました。

## CLI上での使用方法

fuzzufではAFLFastはAFLと同様に使えます。次のようにして実行します。

```bash
fuzzuf aflfast --in_dir=path/to/initial/seeds/ -- path/to/PUT @@
```

指定可能なグローバルなオプションはAFLと同様です。AFLのオプションについては[AFL/algorithm_ja.md](/docs/algorithms/AFL/algorithm_ja.md)を参照してください。
なお、現時点ではAFLFast固有のローカルなオプションはなく、CLIでのスケジュールのオプションが未実装なため、CLIからはFASTのみが利用できます。

## アルゴリズム概要
AFLにおける問題点は、入力生成の効率にありました。あるパス ![i](https://render.githubusercontent.com/render/math?math=i) を実行するシードからパス ![j](https://render.githubusercontent.com/render/math?math=j) を実行する入力が発見されるためには、シードから生成される入力の数（以降エネルギーと呼びます）が重要な要素となります。エネルギーが大きすぎる場合は、最も効果的な手法であっても効率が悪いことが知られており[^tse15]、エネルギーが小さすぎる場合はそもそもパス ![j](https://render.githubusercontent.com/render/math?math=j) を実行する入力が発見できません。AFLでは、このエネルギーをシードのみから一意に決定できる式によって割り当てており、過不足が発生しています。

これに対し、AFLFastに実装されているFASTという手法はエネルギーを指数関数的に割り当てます。すなわち、あるシードが最初にファジングされたときはエネルギーが極めて低く、そのシードが選択されるたびにより多くのエネルギーが割り当てられ、生成される入力の数が増えていきます。このアルゴリズムによって、新しいパスを発見するのに必要なエネルギーをより効率的に発見することができるようになります。


## パワースケジュールについて
AFLFastで使用可能な ![p(i)](https://render.githubusercontent.com/render/math?math=p(i)) を計算するためのパワースケジュールは5種類あります。

### EXPLOIT: exploitation-based constant schedule
AFLを含むほとんどのグレーボックスファザーでは、実行時間やカバレッジ、生成時間からスコア ![\alpha(i)](https://render.githubusercontent.com/render/math?math=%5Calpha%28i%29) を計算し、エネルギーにはこの値をそのまま用います。

![p(i) = \alpha(i)](https://render.githubusercontent.com/render/math?math=p%28i%29%20%3D%20%5Calpha%28i%29)

### EXPLORE: exploration-based constant schedule
探索ベースのスケジュールはEXPLOITと同様に定数ですが、1以上の定数 ![\beta](https://render.githubusercontent.com/render/math?math=%5Cbeta) を用いて次の式で計算されます。

![p(i) = \frac{\alpha(i)}{\beta}](https://render.githubusercontent.com/render/math?math=p%28i%29%20%3D%20%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D)

これは計算された ![\alpha(i)](https://render.githubusercontent.com/render/math?math=%5Calpha%28i%29) を採用しつつ、かなり低いエネルギーを割り当てます。

### COE: Cut-Off Explonential
カットオフ指数は高頻度のパスがファジングされるのを防ぎ、低頻度のパスになるまでファジングしないためのスケジュールです。
頻度の閾値 ![\mu](https://render.githubusercontent.com/render/math?math=%5Cmu) は発見されたパスの集合 ![S^{+}](https://render.githubusercontent.com/render/math?math=S%5E%7B%2B%7D) と ![i](https://render.githubusercontent.com/render/math?math=i) を通る入力の数 ![f(i)](https://render.githubusercontent.com/render/math?math=f%28i%29) を用いて、次の式によって定義されます。

![\mu = \frac{\sum_{i \in S^{+}} f(i)}{|S^{+}|}](https://render.githubusercontent.com/render/math?math=%5Cmu%20%3D%20%5Cfrac%7B%5Csum_%7Bi%20%5Cin%20S%5E%7B%2B%7D%7D%20f%28i%29%7D%7B%7CS%5E%7B%2B%7D%7C%7D)

![f(i)](https://render.githubusercontent.com/render/math?math=f%28i%29) が ![\mu](https://render.githubusercontent.com/render/math?math=%5Cmu) より大きい場合は、他のシードをファジングしてもなお多くファジングされるとみなせるため優先度が低く設定され、再度 ![\mu](https://render.githubusercontent.com/render/math?math=%5Cmu) を下回るまで ![p(i)](https://render.githubusercontent.com/render/math?math=p(i)) が ![0](https://render.githubusercontent.com/render/math?math=0) に設定され、ファジングされません。

![f(i)](https://render.githubusercontent.com/render/math?math=f%28i%29) が ![\mu](https://render.githubusercontent.com/render/math?math=%5Cmu) 以下の場合、![p(i)](https://render.githubusercontent.com/render/math?math=p(i)) は ![s(i)](https://render.githubusercontent.com/render/math?math=s(i)) （![t_i](https://render.githubusercontent.com/render/math?math=t_i) が選ばれた回数）と ![M](https://render.githubusercontent.com/render/math?math=M) （ファジングのイテレーションごとに生成される入力値の数の上限）を用いて、次の式によって計算されます。

![p(i) = \textrm{min}\left(\frac{\alpha(i)}{\beta} \cdot 2^{s(i)}, M\right)](https://render.githubusercontent.com/render/math?math=p%28i%29%20%3D%20%5Ctextrm%7Bmin%7D%5Cleft%28%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D%20%5Ccdot%202%5E%7Bs%28i%29%7D%2C%20M%5Cright%29)

![\frac{\alpha(i)}{\beta} = 1](https://render.githubusercontent.com/render/math?math=%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D%20%3D%201) におけるCOEスケジュールがクラッシュを見つけるまでの入力生成数は、AFLが256,000つだったのに対し4,000と、非常に効率的に入力を生成できることが実験的に判明しています。


### FAST: exponential schedule
COEを拡張した指数スケジュールでは、 ![f(i) > \mu](https://render.githubusercontent.com/render/math?math=f%28i%29%20%3E%20%5Cmu) の場合にファジングしないのではなく、 ![f(i)](https://render.githubusercontent.com/render/math?math=f%28i%29) に反比例した ![p(i)](https://render.githubusercontent.com/render/math?math=p%28i%29) を設定します。

![p(i) = \textrm{min}\left(\frac{\alpha(i)}{\beta} \cdot \frac{2^{s(i)}}{f(i)} , M\right)](https://render.githubusercontent.com/render/math?math=p%28i%29%20%3D%20%5Ctextrm%7Bmin%7D%5Cleft%28%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D%20%5Ccdot%20%5Cfrac%7B2%5E%7Bs%28i%29%7D%7D%7Bf%28i%29%7D%20%2C%20M%5Cright%29)

![f(i)](https://render.githubusercontent.com/render/math?math=f%28i%29) を分母にすることで、ファジングされる頻度が少ないパスにいることが理由でファジングされなかったパスをファジングできるようになります。また指数的な増加をするので、ファジングされる頻度が少ないパスでも確実にファジングできるようになります。

### LINEAR: linear schedule
線形スケジュールは以下の式で表され、 ![p(i)](https://render.githubusercontent.com/render/math?math=p%28i%29) は指数的ではなく線形的に増加します。

![p(i) = \textrm{min}\left(\frac{\alpha(i)}{\beta} \cdot \frac{s(i)}{f(i)}, M\right)](https://render.githubusercontent.com/render/math?math=p%28i%29%20%3D%20%5Ctextrm%7Bmin%7D%5Cleft%28%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D%20%5Ccdot%20%5Cfrac%7Bs%28i%29%7D%7Bf%28i%29%7D%2C%20M%5Cright%29)

### QUAD: quadratic schedule
二次スケジュールは以下の式で表され、 ![p(i)](https://render.githubusercontent.com/render/math?math=p%28i%29) は二次関数的に増加します。

![p(i) = \textrm{min}\left(\frac{\alpha(i)}{\beta} \cdot \frac{s(i)^2}{f(i)}, M\right)](https://render.githubusercontent.com/render/math?math=p%28i%29%20%3D%20%5Ctextrm%7Bmin%7D%5Cleft%28%5Cfrac%7B%5Calpha%28i%29%7D%7B%5Cbeta%7D%20%5Ccdot%20%5Cfrac%7Bs%28i%29%5E2%7D%7Bf%28i%29%7D%2C%20M%5Cright%29)


## 参考文献

[^ccs16]: Marcel Böhme, Van-Thuan Pham, and Abhik Roychoudhury. 2016. Coverage-based Greybox Fuzzing as Markov Chain. In Proceedings of the 23rd ACM Conference on Computer and Communications Security (CCS’16).
[^tse15]: Marcel Bohme and Soumya Paul. 2015. A Probabilistic Analysis of the Efficiency of Automated Software Testing. In IEEE Transactions on Software Engineering (TSE'15).

