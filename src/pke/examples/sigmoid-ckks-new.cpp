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

map<int, Ciphertext<DCRTPoly>> ccMap;

class SigmoidCKKS {
    public:
        uint32_t scaleModSize, batchSize, multDepth, degree;

        vector<double> inputVector, coeff;

        CryptoContext<DCRTPoly> cc;
        KeyPair<DCRTPoly> keyPair;
        Ciphertext<DCRTPoly> ct;

        Plaintext result;

        bool coeffAdded = false;
        int splitCntr = -1; // -1: no split 
        vector<double> splitParts;
        double scaleBy;

        SigmoidCKKS(uint32_t multDepth_, 
                    uint32_t degree_, 
                    vector<double> inputVector_,
                    vector<double> coeff_) {
            this->scaleModSize = 50;
            this->batchSize = 8;
            
            this->degree = degree_;
            this->multDepth = multDepth_ ;
            
            this->inputVector = inputVector_;
            this->coeff = coeff_;      

            initCryptoContext();   
            initKeyPair();
        }

        void enableSplitting(double scaleBy, vector<double> splitParts) {
            this->splitParts = splitParts;
            this->splitCntr = splitParts.size();
            this->scaleBy = scaleBy;
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
                double x = coeff.at(0);
                //cout << "input: " << e << endl;
                //cout << "x = c[0] = " << coeff.at(0) << endl;
                auto i = degree;
                while (i > 0) {
                    if(i % 2) {
                        x += coeff.at(i) * pow(e, i);
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

        void printResults(vector<double> funcResult, vector<double> plainResult, vector<complex<double>> cryptoResult) {
            cout << "\nExpected sigmoid:         " << funcResult << endl;
            cout << "\nExpected approx:          " << plainResult << endl;
            cout << "\nResult:                   " << cryptoResult << endl;

            //double mae_error = mae(sigmoid, finalResult);
            double mapeSigmoid = mape(funcResult, cryptoResult);
            double mapePlain = mape(plainResult, cryptoResult);

            //cout << "\nApproximation error mae:  " << mae_error << endl;
            cout << "\nAccuracy with mape (compared to sigmoid):                " << 100 - mapeSigmoid << "%" << endl;
            cout << "\nAccuracy with mape (compared to plain evaluation):       " << 100 - mapePlain << "%" << endl;
        }

        auto pregenerate(uint32_t degree) {
            vector<Ciphertext<DCRTPoly>> pregen = {ct, ct};

            int a = 1;
            int b = 1;
            for(int i = 0; i < degree + 1; i++) {
                if(!i || i == 1) 
                    continue;
                
                pregen.push_back(cc->EvalMult(pregen[i-a], pregen[i-b]));

                //std::cout << "x^" << i-a << " * " << "x^" << i-b << " = " << i-a+i-b << std::endl;
                
                if(i % 2) // uneven degree 
                    b++;
                else a++; // even degree
            }

            return pregen;
        }

        auto baseWithSplitting(Ciphertext<DCRTPoly> x, double c) {
            if(!coeffAdded) {
                coeffAdded = true;
                //cout << c << " * " << scaleBy << " * x" << endl;
                return cc->EvalMult(c * scaleBy, x);
            }
            if(splitCntr) { // if a part of a split coefficient is still left
                splitCntr--;
                return cc->EvalMult(splitParts[splitCntr], x);
            }
            else {
                return x;
            }
        }

        auto base(Ciphertext<DCRTPoly> x, double c) {
            if(!coeffAdded) {
                    coeffAdded = true;
                    //cout << "c * x" << endl;
                    return cc->EvalMult(c, x);
            }
            else {
                //cout << "x" << endl;
                return x;
            }
        }

        auto evalGen(int power, double c) { 
            Ciphertext<DCRTPoly> x = ct;
            if (power == 1) {
                if(splitCntr != -1) {
                    return baseWithSplitting(x, c);
                }
                return base(x, c);
            }
            else if (power % 2) {// odd 
                //cout  << "x^" << (int) (power / 2) << " * x^" << (int) (power / 2) + 1 << endl;
                // if(ccMap.find(power) == ccMap.end()) {
                //     ccMap[power] = 
                // }
                return cc->EvalMult(evalGen((int) (power / 2), c), evalGen((int) (power / 2) + 1, c));;
                //return cc->EvalMult(evalGen((int) (power / 2), c), evalGen((int) (power / 2) + 1, c));
            }
            else {
                //cout  << "x^" << (int) (power / 2) << " * x^" << (int) (power / 2) << endl;
                return cc->EvalSquare(evalGen(power / 2, c));
            }
        }   

        void evalSum() {
            auto d = degree;

            //cout << "eval = c0 + evalGen(1, c1)" << endl;
            auto eval = cc->EvalAdd(coeff[0], evalGen(1, coeff[1]));
            while (d > 1) {
                //cout << "eval = eval + evalGen(" << d << ", c" << d << ")" << endl;
                coeffAdded = false;
                eval = cc->EvalAdd(eval, evalGen(d, coeff[d]));
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
            encrypt();
            evalSum();
            decrypt();
            return getCryptoResult();
        }
};

uint32_t getMultDepth(uint32_t d) {
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

void evaluate(uint32_t depth, uint32_t degree, std::vector<double> inputVector, std::vector<double> coeff) {
    depth = depth ? depth : getMultDepth(degree);
    SigmoidCKKS sigmoidCKKS(depth, degree, inputVector, coeff);
    cout << "\n#######################################################################" << endl;
    cout << "SPLITTING: OFF" << endl;
    cout << "MUlT DEPTH: " << sigmoidCKKS.multDepth << ", DEGREE " << degree << endl;

    clock_t start = clock();
    vector<complex<double>> cryptoResult = sigmoidCKKS.eval();
    clock_t end = clock();
    
    vector<double> plainResult = sigmoidCKKS.evalPlain();
    vector<double> sigmoidResult = sigmoidCKKS.sigmoidVec();

    sigmoidCKKS.printResults(sigmoidResult, plainResult, cryptoResult);

    cout << "Time: " << ((double)(end - start)) / CLOCKS_PER_SEC << "s" << endl;
}

void evaluateWithSplitting(uint32_t depth, uint32_t degree, std::vector<double> inputVector, std::vector<double> coeff, double scaleBy, vector<double> splitParts) {
    depth = depth ? depth : getMultDepth(degree);
    SigmoidCKKS sigmoidCKKS(depth, degree, inputVector, coeff);
    cout << "\n#######################################################################" << endl;
    cout << "SPLITTING: ON" << endl;
    cout << "MUlT DEPTH: " << sigmoidCKKS.multDepth << ", DEGREE " << degree << endl;

    sigmoidCKKS.enableSplitting(scaleBy, splitParts);

    clock_t start = clock();
    vector<complex<double>> cryptoResult = sigmoidCKKS.eval();
    clock_t end = clock();

    vector<double> plainResult = sigmoidCKKS.evalPlain();
    vector<double> sigmoidResult = sigmoidCKKS.sigmoidVec();

    sigmoidCKKS.printResults(sigmoidResult, plainResult, cryptoResult);

    cout << "Time: " << ((double)(end - start)) / CLOCKS_PER_SEC << "s" << endl;
}

int main() {
    vector<double> coeff({
        5.00000000e-01, 2.26806218e-01, 0.0, -1.07117799e-02,
        0.0,            3.52123152e-04, 0.0, -7.05240422e-06,
        0.0,            8.99430008e-08, 0.0, -7.61584664e-10,
        0.0,            4.39092990e-12, 0.0, -1.73238644e-14,
        0.0,            4.55363956e-17, 0.0, -7.13526151e-20,
        0.0,            3.14409396e-23, 0.0,  1.26765540e-25,
        0.0,           -3.19383669e-28, 0.0,  3.58641748e-31,
        0.0,           -2.09459954e-34, 0.0,  5.15557512e-38,
        0.0
    });

    vector<double> coeff64({
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

    vector<double> inputVector = {0.25, 0.5, 0.75, 1.0, 2.0};

    //evaluateWithSplitting(0, 13, inputVector, coeff, pow(10,12), {(double)(1.0e-06), (double)(1.0e-06)});

    //vector<double> splitParts = {(double)(1.0e-08), (double)(1.0e-08), (double)(1.0e-08), (double)(1.0e-07)};
    //evaluateWithSplitting(0, 27, inputVector, coeff, pow(10,31), splitParts);

    vector<uint32_t> degrees = {13};
    for(uint32_t degree: degrees) {
        evaluate(0, degree, inputVector, coeff);
    }
}