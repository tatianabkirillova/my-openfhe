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

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

class SigmoidCKKS {
    public:
        uint32_t scaleModSize;
        uint32_t batchSize;

        uint32_t multDepth;
        uint32_t degree;

        vector<double> inputVector;
        vector<double> coeff;

        CryptoContext<DCRTPoly> cc;
        KeyPair<DCRTPoly> keyPair;
        Ciphertext<DCRTPoly> ct;

        Plaintext result;

        SigmoidCKKS(uint32_t multDepth_, 
                    uint32_t degree_, 
                    vector<double> inputVector_,
                    vector<double> coeff_) {
            this->scaleModSize = 50;
            this->batchSize = 8;
            
            this->multDepth = multDepth_;
            this->degree = degree_;
            
            this->inputVector = inputVector_;
            this->coeff = coeff_;      

            initCryptoContext();   
            initKeyPair();
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
            double mapePlain = mape(funcResult, plainResult);

            //cout << "\nApproximation error mae:  " << mae_error << endl;
            cout << "\nAccuracy with mape (compared to sigmoid):                " << 100 - mapeSigmoid << "%" << endl;
            cout << "\nAccuracy with mape (compared to plain evaluation):       " << 100 - mapePlain << "%" << endl;
        }

        auto evalGen(int power, double c) { 
            Ciphertext<DCRTPoly> x = ct;
            if (power == 1) 
                return cc->EvalMult(c, x);
            else if (power == 2)
                return cc->EvalMult(x , cc->EvalMult(c, x));
            else if (power == 3)
                return cc->EvalMult(cc->EvalMult(c, x), cc->EvalMult(x, x));
            else if (power % 2) // odd
                return cc->EvalMult(evalGen((int) (power / 2), c), evalGen((int) (power / 2), c));
            else 
                return cc->EvalSquare(evalGen(power / 2, c));
        }   

        void eval13() {   
            auto c_x1 = ct;
            auto c_x2 = cc->EvalMult(c_x1,c_x1);
            auto c_x3 = cc->EvalMult(c_x1,c_x2);
            auto c_x4 = cc->EvalMult(c_x2,c_x2);
            auto c_x5 = cc->EvalMult(c_x2,c_x3);
            
            auto g_t=cc->EvalMult(cc->EvalMult(c_x1,(double)(1.0e-03)),c_x1);//2
            auto g_t1=cc->EvalMult(cc->EvalMult(c_x1,(double)(coeff[9]*pow(10,6))),c_x1);//2

            auto g_t2=cc-> EvalSquare(g_t);//3 x^4
            auto g_t3=cc->EvalMult(g_t1,c_x3);//3 x^5
            
            auto e_t=cc->EvalMult(cc->EvalMult(c_x1,(double)(1.0e-05)),c_x2);//2
            auto e_t1=cc->EvalMult(cc->EvalMult(c_x1,(double)(coeff[11]*pow(10,10))),c_x1);//2

            auto e_t2=cc-> EvalSquare(e_t);//3 x^6
            auto e_t3=cc->EvalMult(e_t1,c_x3);//3 x^5
            
            
            auto f_t=cc->EvalMult(cc->EvalMult(c_x1,(double)(1.0e-06)),c_x2);//2
            auto f_t1=cc->EvalMult(cc->EvalMult(c_x1,(double)(coeff[13]*pow(10,12))),c_x2);//2 why is here coeff 13

            auto f_t2=cc-> EvalSquare(f_t);//3 x^6
            auto f_t3=cc->EvalMult(f_t1,c_x4);//3 x^7
            
            
            auto eval_1 = cc->EvalAdd(cc->EvalMult(c_x1,coeff[1]),coeff[0]);
            auto eval_2 = cc->EvalAdd(cc->EvalMult(cc->EvalMult(c_x2,coeff[3]),c_x1),eval_1);

            auto eval_3 = cc->EvalAdd(cc->EvalMult(cc->EvalMult(c_x3,coeff[5]),c_x2),eval_2);
            auto eval_4 = cc->EvalAdd(cc->EvalMult(cc->EvalMult(c_x4,coeff[7]),c_x3),eval_3);
            auto eval_5 = cc->EvalAdd(cc->EvalMult(g_t2,g_t3),eval_4);
            auto eval_6 = cc->EvalAdd(cc->EvalMult(e_t2,e_t3),eval_5);
            auto eval_7 = cc->EvalAdd(cc->EvalMult(f_t2,f_t3),eval_6);

            ct = eval_7;
        }

        auto eval() {
            encrypt();
            eval13();
            decrypt();
            return getCryptoResult();
        }
};

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

    vector<double> inputVector = {0.25, 0.5, 0.75, 1.0, 2.0};

    uint32_t multDepth = 4;
    uint32_t degree = 13;

    SigmoidCKKS sigmoidCKKS(multDepth, degree, inputVector, coeff);
    vector<complex<double>> cryptoResult = sigmoidCKKS.eval();
    vector<double> plainResult = sigmoidCKKS.evalPlain();
    vector<double> sigmoidResult = sigmoidCKKS.sigmoidVec();

    sigmoidCKKS.printResults(sigmoidResult, plainResult, cryptoResult);
}