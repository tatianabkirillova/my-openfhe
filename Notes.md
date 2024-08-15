The higher degree the more accurate is the approximation.
Too small coefficients result in a computational error
Precision according to IEEE 754 standard:
single precision 32-bit: around 7 decimal digits
double precision 64-bit: around 15-17 decimal digits

degree -> MAPE Accuracy
13 -> 

Expected sigmoid:         [ 0.562177 0.622459 0.679179 0.731059 0.880797 ]

Expected approx degree 7: [ 0.668632 0.667991 0.667237 0.666355 0.661227 ]

Result:                   (0.542979, 0.585682, 0.627836, 0.669175, 0.821422,  ... ); Estimated precision: 43 bits

Accuracy with mape (compared to sigmoid):                93.5822%

Accuracy with mape (compared to plain evaluation):       87.6423%