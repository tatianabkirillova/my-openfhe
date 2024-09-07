#include <math.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>
#include <cmath>
#include "openfhe.h"
#include "stdio.h"
#include "time.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

class SigmoidCKKS {
    public:
        uint32_t scaleModSize, batchSize, multDepth, degree;

        vector<double> inputVector, coeffs;

        map<int, Ciphertext<DCRTPoly>> xMap;

        CryptoContext<DCRTPoly> cc;
        KeyPair<DCRTPoly> keyPair;
        Ciphertext<DCRTPoly> ct;

        Plaintext result;

        bool splittingEnabled;
        bool poly;

        SigmoidCKKS(uint32_t multDepth_, 
                    uint32_t degree_, 
                    vector<double> inputVector_,
                    vector<double> coeffs_,
                    bool splittingEnabled_,
                    bool poly_) {
            this->scaleModSize = 50;
            this->batchSize = 8;
            
            this->degree = degree_;
            this->multDepth = multDepth_ ? multDepth_ : getMultDepth();
            
            this->inputVector = inputVector_;
            this->coeffs = coeffs_;    

            this->splittingEnabled = splittingEnabled_;
            this->poly = poly_;

            initCryptoContext();   
            initKeyPair();
        }

        uint32_t getMultDepth() {
            uint32_t d = degree;
            if(d < 4) 
                return 2;
            if(d < 8) 
                return 3;
            if(d < 16) 
                return 4;
            if(d < 32) 
                return 5;
            if(d < 64)
                return 6;
            else
                return 0;
        }

        vector<double> getSplitCoeff(double c) {
            vector<double> splitCoeff;
            if (abs(c) < (double)(1.0e-80)) {
                cout << "abs(c) < (double)(1.0e-80) " << c << endl;
                splitCoeff.push_back(c * (1.0e80));
                for(int i = 0; i < 16; i++) {
                    splitCoeff.push_back((double)(1.0e-05));
                }
            }
            else if (abs(c) < (double)(1.0e-40)) {
                cout << "abs(c) < (double)(1.0e-80) " << c << endl;
                splitCoeff.push_back(c * (1.0e40));
                for(int i = 0; i < 8; i++) {
                    splitCoeff.push_back((double)(1.0e-05));
                }
            }
            else if (abs(c) < (double)(1.0e-20)) {
                cout << "abs(c) < (double)(1.0e-80) " << c << endl;
                splitCoeff.push_back(c * (1.0e20));
                for(int i = 0; i < 4; i++) {
                    splitCoeff.push_back((double)(1.0e-05));
                }
            }
            else if (abs(c) < (double)(1.0e-10)) { 
                cout << "abs(c) < (double)(1.0e-80) " << c << endl;
                splitCoeff.push_back(c * (1.0e10));
                for(int i = 0; i < 2; i++) {
                    splitCoeff.push_back((double)(1.0e-05));
                }                
            }
            return splitCoeff;
        }

        void initCryptoContext() {
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetMultiplicativeDepth(multDepth);
            parameters.SetScalingModSize(scaleModSize);
            parameters.SetBatchSize(batchSize);

            cc = GenCryptoContext(parameters);
            // Enable features that you wish to use
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);
            cc->Enable(ADVANCEDSHE);

            cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << endl << endl;
        }

        void initKeyPair() {
            // Generate a public/private key pair
            keyPair = cc->KeyGen();

            // Generate the relinearization key
            cc->EvalMultKeyGen(keyPair.secretKey);
        }

        void encrypt() {
            Plaintext ptEncoded = cc->MakeCKKSPackedPlaintext(inputVector);
            ct = cc->Encrypt(keyPair.publicKey, ptEncoded);
        }

        void decrypt() {
            cc->Decrypt(keyPair.secretKey, ct, &result);
            result->SetLength(inputVector.size());
        }

        vector<complex<double>> getCryptoResult() {
            return result->GetCKKSPackedValue();
        }

        double sigmoid(double x) {
            return 1.0 / (1.0 + exp(-x));
        }

        vector<double> sigmoidVec() {
            vector<double> result;
            for(auto e : inputVector) {
                result.push_back(sigmoid(e));
            }
            return result;
        }

        auto evalPlain() {
            vector<double> plainResult;
            //cout << "##### eval plain #####" << endl;
            for(auto e : inputVector) {
                double x = coeffs.at(0);
                //cout << "input: " << e << endl;
                //cout << "x = c[0] = " << coeff.at(0) << endl;
                auto i = degree;
                while (i > 0) {
                    if(i % 2) {
                        x += coeffs.at(i) * pow(e, i);
                        //cout << "degree: " << i << endl;
                        //cout << "x = c[" << i << "] = " << coeff.at(i) << " * " << e << "^" << i << endl;
                    }
                    i--;
                }
                plainResult.push_back(x);
            }
            //cout << "######################" << endl;
            return plainResult;
        }
        
        template <typename T>
        auto mape(vector<double> original, vector<T> approx) {
            double error = 0;
            for(int i = 0; i < original.size(); i++){
                if(original[i] != 0) {
                    double diff = 0;
                    if constexpr (is_same<T, complex<double>>::value)
                        diff = fabs(original[i] - approx[i].real()) / original[i];
                    else 
                        diff = fabs(original[i] - approx[i]) / original[i];
                    
                    error += diff;
                }
            }
            
            return error * 100 / original.size();
        } 

        template <typename T>
        auto mse(std::vector<double> original, std::vector<T> approx) {
            double error = 0;
            for(int i = 0; i < original.size(); i++){
                auto diff = 0;
                if constexpr (std::is_same<T, std::complex<double>>::value)
                    diff = original[i] - approx[i].real();
                else
                    diff = original[i] - approx[i];
                error += diff * diff;
            }
            
            return error / original.size() * 100;
        } 

        void printResults(vector<double> funcResult, vector<double> plainResult, vector<complex<double>> cryptoResult) {
            cout << "\n#######################################################################" << endl;
            cout << "SPLITTING: " << (splittingEnabled ? "ON" : "OFF") << endl;
            cout << "MUlT DEPTH: " << multDepth << ", DEGREE " << degree << endl;

            cout << "\nExpected sigmoid:         " << funcResult << endl;
            cout << "\nExpected approx:          " << plainResult << endl;
            cout << "\nResult:                   " << cryptoResult << endl;

            double mseSigmoid = mse(funcResult, cryptoResult);
            double msePlain = mse(plainResult, cryptoResult);

            cout << "\nAccuracy with mse (compared to sigmoid):                " << 100 - mseSigmoid << "%" << endl;
            cout << "\nAccuracy with mse (compared to plain evaluation):       " << 100 - msePlain << "%" << endl;
        }

        void pregenerate(uint32_t degree) {
            xMap[1] = ct;
            
            uint32_t power = 2;
            while(power <= degree) { 
                if(power % 2) { // odd power
                    xMap[power] = cc->EvalMult(xMap[(int) (power / 2)], xMap[(int) (power / 2) + 1]);
                }
                else { // even power
                    xMap[power] = cc->EvalSquare(xMap[power / 2]);
                }
                power++;
                //std::cout << "x^" << i-a << " * " << "x^" << i-b << " = " << i-a+i-b << std::endl;
            }
        }

        auto evalTreeSplitting(int power, vector<double> splitCoeff, bool fromOdd) {
            auto size = splitCoeff.size();
            printf("cntr: %zu\n", size);

            Ciphertext<DCRTPoly> x = ct;
            if (power == 1) {
                if(fromOdd && size) {
                    Ciphertext<DCRTPoly> cx = cc->EvalMult(splitCoeff[size - 1], x);
                    splitCoeff.pop_back();
                    return cx;
                }
                return x;
            }
            else if (power % 2) { // odd
                return cc->EvalMult(evalTreeSplitting((int) (power / 2), splitCoeff, true), evalTreeSplitting((int) (power / 2) + 1, splitCoeff, true));
            }
            else { // even
                //cout  << "x^" << (int) (power / 2) << " * x^" << (int) (power / 2) + 1 << endl;
                return cc->EvalMult(evalTreeSplitting((int) (power / 2), splitCoeff, false), evalTreeSplitting((int) (power / 2), splitCoeff, false));
            }
        }

        void evalSumSplitting() {
            pregenerate(degree);

            //cout << "eval = c0 + evalTree(1, c1)" << endl;
            auto d = degree;
            auto eval = cc->EvalAdd(coeffs[0], evalTreeSplitting(1, getSplitCoeff(coeffs[1]), true));
            while (d > 1) {
                //cout << "eval = eval + evalTree(" << d << ", c" << d << ")" << endl;
                eval = cc->EvalAdd(eval, evalTreeSplitting(d, getSplitCoeff(coeffs[d]), d % 2));
                d--;
            }

            ct = eval;
        }

        auto evalTree(int power, double c) { 
            Ciphertext<DCRTPoly> x = ct;
            if (power == 1) {
                return cc->EvalMult(c, x);
            }
            else if (power % 2) { // odd
                return cc->EvalMult(evalTree((int) (power / 2), c), xMap[(int) (power / 2) + 1]);
            }
            else { // even
                //cout  << "x^" << (int) (power / 2) << " * x^" << (int) (power / 2) + 1 << endl;
                return cc->EvalMult(evalTree((int) (power / 2), c), xMap[(int) (power / 2)]);
            }
        }   

        void evalSum() {
            pregenerate(degree);

            //cout << "eval = c0 + evalTree(1, c1)" << endl;
            auto d = degree;
            auto eval = cc->EvalAdd(coeffs[0], evalTree(1, coeffs[1]));
            while (d > 1) {
                //cout << "eval = eval + evalTree(" << d << ", c" << d << ")" << endl;
                eval = cc->EvalAdd(eval, evalTree(d, coeffs[d]));
                d--;
            }

            ct = eval;
        }

        // auto evalHard() {
        //     encrypt();
        //     eval13();
        //     decrypt();
        //     return getCryptoResult();
        // }

        auto eval() {
            clock_t start = clock();
            encrypt();
            if(splittingEnabled) {
                evalSumSplitting();
            }
            else if(poly) {
                cout << "EVAL POLY" << endl;
                coeffs.resize(degree + 1);
                ct = cc->EvalPoly(ct, coeffs);
            }
            else {
                evalSum();
            }
            decrypt();
            clock_t end = clock();
            
            vector<complex<double>> cryptoResult = getCryptoResult();
            printResults(sigmoidVec(), evalPlain(), cryptoResult);

            cout << "Time: " << ((double)(end - start)) / CLOCKS_PER_SEC << "s" << endl;

            return cryptoResult;
        }
};

int main() {
    vector<double> coeffs({
        5.00000040e-01,  2.30471326e-01, 0.0, -1.15966777e-02,
        0.0,  4.14001861e-04, 0.0, -9.00416843e-06,
        0.0,  1.23093356e-07, 0.0, -1.08863956e-09,
        0.0,  6.26828119e-12, 0.0, -2.27727349e-14,
        0.0,  4.60913867e-17, 0.0, -2.48330461e-20,
        0.0, -8.02256355e-23, 0.0,  7.97430953e-26,
        0.0,  1.95054524e-28, 0.0, -9.09383811e-32,
        0.0, -5.29697493e-34, 0.0, -3.04081080e-37,
        0.0,  9.26855915e-40, 0.0,  1.96046144e-42,
        0.0,  5.15564762e-46, 0.0, -4.11277119e-48,
        0.0, -7.89281977e-51, 0.0, -2.56943432e-54,
        0.0,  1.60781939e-56, 0.0,  3.42734760e-59,
        0.0,  1.56773027e-62, 0.0, -6.68264494e-65,
        0.0, -1.51497884e-67, 0.0, -3.53374778e-71,
        0.0,  4.08063017e-73, 0.0,  4.94504157e-76,
        0.0, -1.39242763e-78, 0.0,  6.98110480e-82,
        0.0
    });

    vector<vector<double>> inputs;
    vector<double> inputVector = {0.25, 0.5, 0.75, 1.0, 2.0};

    inputs.push_back({0.8292, 0.2124, 0.4418, 0.1135, 0.0177});
    inputs.push_back({0.4157, 0.3776, 0.0808, 0.7062, 0.0524});
    inputs.push_back({0.6659, 0.0601, 0.3564, 0.5814, 0.8935});
    inputs.push_back({0.4320, 0.8598, 0.9240, 0.4750, 0.2853});
    inputs.push_back({0.1592, 0.4597, 0.6286, 0.1642, 0.2811});
    inputs.push_back({0.7737, 0.8393, 0.1580, 0.4933, 0.9973});
    inputs.push_back({0.8997, 0.8043, 0.7954, 0.0918, 0.4436});
    inputs.push_back({0.7965, 0.6646, 0.8311, 0.7833, 0.4030});
    inputs.push_back({0.1581, 0.7397, 0.6560, 0.2352, 0.0388});
    inputs.push_back({0.0761, 0.1767, 0.1927, 0.5325, 0.4199});

    //evaluateWithSplitting(0, 13, inputVector, coeff, pow(10,12), {(double)(1.0e-06), (double)(1.0e-06)});

    //vector<double> splitCoeff = {(double)(1.0e-08), (double)(1.0e-08), (double)(1.0e-08), (double)(1.0e-07)};
    //evaluateWithSplitting(0, 27, inputVector, coeff, pow(10,31), splitCoeff);

    vector<uint32_t> degrees = {13, 31};
    for(auto input: inputs) {
        // SigmoidCKKS sigmoidCKKS(0, degree, inputVector, coeffs, false, false);
        // sigmoidCKKS.eval();
        SigmoidCKKS sigmoidCKKSpoly(0, 13, input, coeffs, false, false);
        sigmoidCKKSpoly.eval();
    }
}