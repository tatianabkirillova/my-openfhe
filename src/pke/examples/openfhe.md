---
sidebar_label: 'OpenFHE Concept'
sidebar_position: 3
---

The goal of this research is to test and evaluate the performance of different activation functions on homomorphically encrypted input and enhance the OpenFHE library.  

# Introduction:

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

# Background
## Homomorphic encryption
+ ability to perform computations on encrypted data
## OpenFHE
+ One of the 
## CKKS Scheme
## Machine learning 
## Activation functions

# Results 


# Citations:

+ Behera, S., & Prathuri, J. R. (2020). Application of Homomorphic Encryption in Machine Learning. 2020 2nd PhD Colloquium on Ethically Driven Innovation and Technology for Society (PhD EDITS). doi:10.1109/phdedits51180.2020.9315305 

# TO-DO:

OK: plain evaluation till a given degree

O: degree 13 should give accuracy of 96.60 (96.5955) 

O: encrypted evaluation till a given degree w/o splitting the the coefficients

O: test the accuracy

O: figure out when to split coefficients: thresholds

O: generate coefficients with polyfit

O: test different 

# Accuricies

Using MAPE to measure accuracy 

## Degree = 13

Expected sigmoid:         [ 0.562177 0.622459 0.679179 0.731059 0.880797 ]

Expected approx:          [ 0.542979 0.585682 0.627836 0.669175 0.821422 ]

Result:                   (0.542979, 0.585682, 0.627836, 0.669175, 0.821422,  ... ); Estimated precision: 43 bits


Accuracy with mape (compared to sigmoid):                93.5822%

Accuracy with mape (compared to plain evaluation):       93.5822%

## Degree = 15