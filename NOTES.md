---
sidebar_label: 'OpenFHE Concept'
sidebar_position: 3
---

The goal of this research is to test and evaluate the performance of different activation functions on homomorphically encrypted input and enhance the OpenFHE library.  

# Introduction: - 2p

+ general background
+ clear motivation for my main reasearch problem or thesis goal
  + why is it relevant?
  + if you have a central research question, state it clearly 
  + include papers relevant to your work
  + focus on final outcome rather than the journey
  + everything is happening now and is done by "we"
  + include details about how the results were achieved, like hardware/sofware, model, schemes.
  + contextualize my contribution with related work
  + mention related work in the Background or final Discussion section

# Background - 10p
## Homomorphic encryption - 2p
+ ability to perform computations on encrypted data
## OpenFHE 9p
+ One of the 
## Different schemes, especially CKKS Scheme 1p
## Applications in Machine learning 2p
## Activation functions 1p

# Polynomial approximation 1p
# Degrees 1p
# Implementation 5p

# Results 

# Conclusion 1p

# Citations:

+ Behera, S., & Prathuri, J. R. (2020). Application of Homomorphic Encryption in Machine Learning. 2020 2nd PhD Colloquium on Ethically Driven Innovation and Technology for Society (PhD EDITS). doi:10.1109/phdedits51180.2020.9315305 

# TO-DO:

- [x] plain evaluation till a given degree
- [x] degree 13 should give accuracy of 96.60 (96.5955) -> 98.6
- [x] generate coefficients with polyfit
- [x] plot to check coefficients
- [ ] try generating coeffs from more points
- [x] encrypted evaluation till a given degree w/o splitting the the coefficients
- [x] test the accuracy
- [ ] figure out when to split coefficients: thresholds
- [ ] test different functions
- [ ] figure out what parameters scaleModSize & batchSize do

# Polyfit

I use numpy.polynomial to generate coefficients for the chebyshev approximation of the sigmoid function

# Accuracies

Using MAPE to measure accuracy 

# Splitting 

The higher degree the more accurate is the approximation.

Too small coefficients result in a computational error

Precision according to IEEE 754 standard:

single precision 32-bit: around 7 decimal digits

double precision 64-bit: around 15-17 decimal digits

# Errors

```
Plaintext: (0.25, 0.5, 0.75, 1, 2,  ... ); Estimated precision: 50 bits

terminate called after throwing an instance of 'lbcrypto::OpenFHEException'
  what():  /home/tatiana/BA/my-openfhe/src/pke/lib/encoding/ckkspackedencoding.cpp:l.537:Decode(): The decryption failed because the approximation error is too high. Check the parameters. 
Aborted (core dumped)

```
The error means the set multiplicative depth is too small
