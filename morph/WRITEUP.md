# Morph - Solution

It's all about textbook RSA being [homomorphic](https://en.wikipedia.org/wiki/Homomorphism).

On the Info page we can see the code that is used to generate and validate vouchers. From the code we can see that it is RSA being used. The public parameters are

```python
sage: N = 27896443183940410519925396123323059650036887769686716183236371884408263173828495411505152190021430063765215594314572188185470824836625203861010850736928460774206270229437724504379533316272287787989963320955280842495256279436898508142007272510209427291135240223609521995116889527886827963139018353353017709086587650049644066530636415742640727010109654139292899207197866857799917353848028590201320328502967680754379678965653049868642291008018630015254694785758982303136296904756161917531550979498419603371739519690632442576693718121499495066636741768674983030991426933479523439799481311406050358667905567860811830074707
sage: e = 65537
```

A voucher for a morph ID is simply a textbook RSA signature of the given ID. The private parameter `d` is used for signing:

```text
voucher = (id + 1)^d mod N
```

We know from the Info page that `e*d = 1 mod phi(N)`.

The task is to get a voucher for the Flag Morph with ID 6. However, the voucher generator generates vouchers for all IDs but ID 6.

To still get a valid voucher without knowing the secret `d`, we can exploit that textbook RSA is malleable due to its homomorphism property. Because RSA is homomorphic, we know that if `a^d mod N = A` and `b^d mod N = B`, then `(a*b)^d mod N = A*B mod N`. We can use this to compute a valid voucher for ID 6.

Because every ID is incremented by one before being signed, we are searching for the signature of the number 7.

```text
7^d = (7 * 1)^d              mod N
    = (7 * x * x^-1)^d       mod N
    = (7 * x)^d * (x^-1)^d   mod N
```

This equation shows us that we can compute `7^d mod N` by multiplying the vouchers for `7*x - 1` and `x^-1 - 1` (remember that 1 is added to every product ID before computing the voucher so we have to substract 1).

We can choose x as any number that has an inverse modulo N. All numbers that don't have a common divisor with N have an inverse and since N only has two huge divisors, any small number can be chosen here.

So let's choose `x = 2`.

Of course, `7*2 - 1 = 13` and  `2^-1 - 1 mod N` are no IDs belonging to a valid product. But the voucher generator will output a valid voucher anyways, so we can use these vouchers to compute the target voucher.

But before we do that, we have to find the inverse of 2 modulo N. To do so, we use SageMath:

```python
sage: x = 2
sage: inverse_mod(x, N)
13948221591970205259962698061661529825018443884843358091618185942204131586914247705752576095010715031882607797157286094092735412418312601930505425368464230387103135114718862252189766658136143893994981660477640421247628139718449254071003636255104713645567620111804760997558444763943413981569509176676508854543293825024822033265318207871320363505054827069646449603598933428899958676924014295100660164251483840377189839482826524934321145504009315007627347392879491151568148452378080958765775489749209801685869759845316221288346859060749747533318370884337491515495713466739761719899740655703025179333952783930405915037354
```

The voucher for `13` is

```python
sage: A = 7651083422268021507023534503313253685937175934385936035933836494093622894943395990790331498586146160129047969856931674942953498557583648002740623239257026951496057852526671136556967993412702145472744515365224879055928991506830874822350455507667853707960497711643180206251703982370426937963410441251947347636079712116393905617491412528588454396991438525629509288547856095238351879687745667523645724563776745781801092729349566463913094304692706335735750937695020014863918570486668685745827594335013722366624877381764930144927567980012147628872321337233029938706828254199534333230472861032313300149033655694873115859847
```

And the voucher for `(2^-1 mod N) - 1` is

```python
sage: B = 4921685945764258852734720652402103054470417556765953210206405990592439594982870732084668769497822533772753927740740558287563438562149590989320239324582586855788371682473141011719284532092000831108437323413720567254199952707636425806222137527986195318714386680173461584888447529593001417401751828993575330346032768994019383090436069774172177955997937450733331238200428741498499345010697362588835605940044477995365076524859273625818661856431654397909819505645861680414124183591323700273136699291384959559704418973752897098852720317291804302194560113432889825328693667434391704439892121221064781931511464508854362091450
```

We compute the target voucher for the Flag Morph with ID 6:

```python
sage: voucher = (A * B) % N
sage: voucher
19072010055064548399093759020938779623123952572929317502826665522323333599457980656573211831941964325418499313813651073388220538227861501838224576002831372926027452297152870833533987954041437674150442889229619298291490272919310273728169470054952160286973985765551403903432069268257336699415351074045876438094125772732533021476033828917497591281373905281062996629198427178375435494108396543047870406167058283561410224208347674235903145102652372220423306112455256463549521783148841534037656950129707667666851815703100200519575261926687494053569131848879620703435309261413650115730676338789960690530688167946291253230568
```

We can check whether the voucher is valid using the public value `e`:

```python
sage: ((6 + 1) % N) == pow(voucher, e, N)
True
```

So we can go back to the website and get the Flag Morph using the computed voucher. It gives us the flag:

`SSH{Textb00kRSA_1s_m4ll3able.}`