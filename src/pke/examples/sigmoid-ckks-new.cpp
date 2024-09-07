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

        bool splittingEnabled = false;
        vector<double> splitCoeff;

        SigmoidCKKS(uint32_t multDepth_, 
                    uint32_t degree_, 
                    vector<double> inputVector_,
                    vector<double> coeffs_) {
            this->scaleModSize = 50;
            this->batchSize = 8;
            
            this->degree = degree_;
            this->multDepth = multDepth_ ? multDepth_ : getMultDepth();
            
            this->inputVector = inputVector_;
            this->coeffs = coeffs_;      

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

        void enableSplitting() {
            splittingEnabled = true;
            for(auto &c : coeffs) {    
                if (abs(c) < (double)(1.0e-80)) {
                    c = c * (1.0e80);
                    for(int i = 0; i < 16; i++) {
                        splitCoeff.push_back((double)(1.0e-05));
                    }
                }
                else if (abs(c) < (double)(1.0e-40)) {
                    c = c * (1.0e40);
                    for(int i = 0; i < 8; i++) {
                        splitCoeff.push_back((double)(1.0e-05));
                    }
                }
                else if (abs(c) < (double)(1.0e-20)) {
                    c = c * (1.0e20);
                    for(int i = 0; i < 4; i++) {
                        splitCoeff.push_back((double)(1.0e-05));
                    }
                }
                else if (abs(c) < (double)(1.0e-10)) { 
                    c = c * (1.0e10);
                    for(int i = 0; i < 2; i++) {
                        splitCoeff.push_back((double)(1.0e-05));
                    }                
                }
            }
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

        void printResults(vector<double> funcResult, vector<double> plainResult, vector<complex<double>> cryptoResult) {
            cout << "\n#######################################################################" << endl;
            cout << "SPLITTING: " << (splittingEnabled ? "ON" : "OFF") << endl;
            cout << "MUlT DEPTH: " << multDepth << ", DEGREE " << degree << endl;

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

        void pregenerate(uint32_t degree) {
            Ciphertext<DCRTPoly> x = ct;
            
            xMap[1] = x;
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

        auto evalGen(int power, double c) { 
            Ciphertext<DCRTPoly> x = ct;
            if (power == 1) {
                return cc->EvalMult(c, x);
            }
            else {// odd 
                //cout  << "x^" << (int) (power / 2) << " * x^" << (int) (power / 2) + 1 << endl;
                return cc->EvalMult(evalGen((int) (power / 2), c), xMap[(int) (power / 2) + 1]);
            }
        }   

        void evalSum() {
            pregenerate(degree);

            //cout << "eval = c0 + evalGen(1, c1)" << endl;
            auto d = degree;
            auto eval = cc->EvalAdd(coeffs[0], evalGen(1, coeffs[1]));
            while (d > 1) {
                //cout << "eval = eval + evalGen(" << d << ", c" << d << ")" << endl;
                eval = cc->EvalAdd(eval, evalGen(d, coeffs[d]));
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
            evalSum();
            decrypt();
            clock_t end = clock();
            
            vector<complex<double>> cryptoResult = getCryptoResult();
            printResults(sigmoidVec(), evalPlain(), cryptoResult);

            cout << "Time: " << ((double)(end - start)) / CLOCKS_PER_SEC << "s" << endl;

            return cryptoResult;
        }
};

void evaluateWithSplitting(uint32_t depth, uint32_t degree, std::vector<double> inputVector, std::vector<double> coeff, double scaleBy, vector<double> splitCoeff) {
    SigmoidCKKS sigmoidCKKS(depth, degree, inputVector, coeff);

    sigmoidCKKS.enableSplitting();

    clock_t start = clock();
    vector<complex<double>> cryptoResult = sigmoidCKKS.eval();
    clock_t end = clock();

    vector<double> plainResult = sigmoidCKKS.evalPlain();
    vector<double> sigmoidResult = sigmoidCKKS.sigmoidVec();

    sigmoidCKKS.printResults(sigmoidResult, plainResult, cryptoResult);

    cout << "Time: " << ((double)(end - start)) / CLOCKS_PER_SEC << "s" << endl;
}

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

    vector<double> inputVector = {0.25, 0.5, 0.75, 1.0, 2.0};

    //evaluateWithSplitting(0, 13, inputVector, coeff, pow(10,12), {(double)(1.0e-06), (double)(1.0e-06)});

    //vector<double> splitCoeff = {(double)(1.0e-08), (double)(1.0e-08), (double)(1.0e-08), (double)(1.0e-07)};
    //evaluateWithSplitting(0, 27, inputVector, coeff, pow(10,31), splitCoeff);

    vector<uint32_t> degrees = {13, 27, 63};
    for(uint32_t degree: degrees) {
        SigmoidCKKS sigmoidCKKS(0, degree, inputVector, coeffs);
        sigmoidCKKS.eval();
    }
}