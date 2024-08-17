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
- [ ] transform to python?
- [ ] figure out what parameters scaleModSize & batchSize do

# Polyfit

I use numpy.polynomial to generate coefficients for the chebyshev approximation of the sigmoid function

# Accuracies

Using MAPE to measure accuracy 

