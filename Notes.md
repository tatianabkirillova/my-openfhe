The higher degree the more accurate is the approximation.

Too small coefficients result in a computational error

Precision according to IEEE 754 standard:

single precision 32-bit: around 7 decimal digits

double precision 64-bit: around 15-17 decimal digits


degree -> MAPE Accuracy

# Mult depth: 5 (depth 4 only works for degree 7 for some reason)
# old coefficients:
## Degree 13 

```
Expected sigmoid:         [ 0.562177 0.622459 0.679179 0.731059 0.880797 ]

Expected approx degree 7: [ 0.668632 0.667991 0.667237 0.666355 0.661227 ]

Result:                   (0.542979, 0.585682, 0.627836, 0.669175, 0.821422,  ... ); Estimated precision: 43 bits

Accuracy with mape (compared to sigmoid):                93.5822%

Accuracy with mape (compared to plain evaluation):       87.6423%
```

# new coeffs (generated with Polynomial.fit())
## Degree 13 

```
Expected sigmoid:         [ 0.562177 0.622459 0.679179 0.731059 0.880797 ]

Expected approx:          [ 0.556535 0.612075 0.665668 0.71644 0.878328 ]

Result:                   [ (0.556535,0) (0.612075,0) (0.665668,0) (0.71644,0) (0.878328,0) ]

Accuracy with mape (compared to sigmoid):                98.6118% 

Accuracy with mape (compared to plain evaluation):       98.6118%
Plaintext: (0.25, 0.5, 0.75, 1, 2,  ... ); Estimated precision: 50 bits
```

This is the same result I get as Aikata's 

## Degree 31

```
Plaintext: (0.25, 0.5, 0.75, 1, 2,  ... ); Estimated precision: 50 bits

terminate called after throwing an instance of 'lbcrypto::OpenFHEException'
  what():  /home/tatiana/BA/my-openfhe/src/pke/lib/encoding/ckkspackedencoding.cpp:l.537:Decode(): The decryption failed because the approximation error is too high. Check the parameters. 
Aborted (core dumped)

```
The error means the set multiplicative depth is too small

