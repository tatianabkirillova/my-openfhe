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

// generated by polyfit
std::vector<double> coeff1({ 
    0.5000000000000107, 0.17209906934813146,    0.0, -0.0029501761301167426, 
    0.0,                2.6262363172485713e-05, 0.0, -1.1845866975589415e-07, 
    0.0,                2.801559311285922e-10,  0.0, -3.3145939768213955e-13, 
    0.0,                1.546695810026845e-16
}); //This gives 96.60 (96.5955) accuracy 

std::vector<double> coeff({
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

std::vector<double> inputVector = {0.25, 0.5, 0.75, 1.0, 2.0};

uint32_t scaleModSize = 50;
uint32_t batchSize = 8;
uint32_t multDepth = 4;

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
        //error += approx[i].real() - mult[(int)(i/d)][i%d];
    }
    
    return error / (double) original.size();
} 

template <typename T>
auto mae(std::vector<double> original, std::vector<T> approx) {
    double error = 0;
    for(int i = 0; i < original.size(); i++){
        auto diff = 0;
        if constexpr (std::is_same<T, std::complex<double>>::value)
            diff = original[i] - approx[i].real();
        else
            diff = original[i] - approx[i];
        error += (diff < 0 ? -diff : diff);
    }
    
    return error / (double) original.size();
} 

template <typename T>
auto mape(std::vector<double> original, std::vector<T> approx) {
    double error = 0;
    for(int i = 0; i < original.size(); i++){
        if(original[i] != 0) {
            double diff = 0;
            if constexpr (std::is_same<T, std::complex<double>>::value)
                diff = fabs(original[i] - approx[i].real()) / original[i];
            else 
                diff = fabs(original[i] - approx[i]) / original[i];
            
            error += diff;
        }
    }
    
    return error * 100 / original.size();
} 

double sigmoid(double x) {
    return 1.0 / (1.0 + exp(-x));
}

std::vector<double> sigmoidVec() {
    std::vector<double> result;
    for(auto e : inputVector) {
        result.push_back(sigmoid(e));
    }
    return result;
}

CryptoContext<DCRTPoly> getCryptoContext() {
    // Step 1: Set CryptoContext
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl << std::endl;

    return cc;
}

auto getKeyPair(CryptoContext<DCRTPoly> cc) {
    // Generate a public/private key pair
    auto keyPair = cc->KeyGen();

    // Generate the relinearization key
    cc->EvalMultKeyGen(keyPair.secretKey);
 
    return keyPair;
}

std::vector<double> evalPlain(uint32_t degree) {
    //std::cout << "##### eval plain #####" << std::endl;
    std::vector<double> xs; 
    for(auto e : inputVector) {
        double x = coeff.at(0);
        //std::cout << "input: " << e << std::endl;
        //std::cout << "x = c[0] = " << coeff.at(0) << std::endl;
        auto i = degree;
        while (i > 0) {
            if(i % 2) {
                x += coeff.at(i) * pow(e, i);
                //std::cout << "degree: " << i << std::endl;
                //std::cout << "x = c[" << i << "] = " << coeff.at(i) << " * " << e << "^" << i << std::endl;
            }
            i--;
        }
        xs.push_back(x);
    }
    //std::cout << "######################" << std::endl;
    return xs;
}

auto evalTreeLeft(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ct, int degree) {  // with coeffs
    // switch (degree)
    // {
    //     case 1:
    //         cc->EvalMult(coeff[1], ct);
    //         break;
    //     case 2: 
    //         cc->EvalMult(coef)
    //     default:
    //         break;
    // }
}

auto evalTreeRight() { // no coeffs
}

// auto eval(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ct, int degree) {
//     auto c_x = evalGen(cc, ct, degree);

//     // Add
//     auto evalResult = cc->EvalAdd(cc->EvalMult(c_x[1], coeff[1]), coeff[0]);
//     for (int i = 2; i < c_x.size(); i++) {
//         evalResult = cc->EvalAdd(cc->EvalMult(c_x[i], coeff[i]), evalResult);
//     }

//     return evalResult;
// }

auto eval13(CryptoContext<DCRTPoly> cc, Ciphertext<DCRTPoly> ct)
{   
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

    return eval_7;
}


void printResults(std::vector<double> funcResult, std::vector<double> plainResult, std::vector<std::complex<double>> result) {
    std::cout << "\nExpected sigmoid:         " << funcResult << std::endl;
    std::cout << "\nExpected approx:          " << plainResult << std::endl;
    std::cout << "\nResult:                   " << result << std::endl;

    //double mae_error = mae(sigmoid, finalResult);
    double mapeSigmoid = mape(funcResult, result);
    double mapePlain = mape(funcResult, plainResult);

    //std::cout << "\nApproximation error mae:  " << mae_error << std::endl;
    std::cout << "\nAccuracy with mape (compared to sigmoid):                " << 100 - mapeSigmoid << "%" << std::endl;
    std::cout << "\nAccuracy with mape (compared to plain evaluation):       " << 100 - mapePlain << "%" << std::endl;
}

int main() {
    // Get crypto context
    CryptoContext<DCRTPoly> cc = getCryptoContext();
    KeyPair<DCRTPoly> keyPair = getKeyPair(cc);
    Plaintext ptEncoded = cc->MakeCKKSPackedPlaintext(inputVector);
    Ciphertext<DCRTPoly> ct = cc->Encrypt(keyPair.publicKey, ptEncoded);


    std::cout << "-----------------------------------------------------------------------" << std::endl;
    std::cout << "Manual evaluation degree 13:" << std::endl;
    std::cout << "-----------------------------------------------------------------------" << std::endl;

    Plaintext result;
    cc->Decrypt(keyPair.secretKey, eval13(cc, ct), &result);
    result->SetLength(inputVector.size());

    std::vector<double> resultPlain = evalPlain(5);
    std::vector<double> sigmoid = sigmoidVec();

    std::vector<std::complex<double>> finalResult = result->GetCKKSPackedValue();

    printResults(sigmoid, resultPlain, finalResult);

    // std::cout << "\n-----------------------------------------------------------------------" << std::endl;
    // std::cout << "Generated..." << std::endl;
    // std::cout << "-----------------------------------------------------------------------" << std::endl;
    // std::vector<int> degrees {7, 13, 16, 31, 32, 33};

    // for (int degree: degrees) {
    //     std::cout << "Checking degree " << degree << std::endl;
    //     //evalGen(cc, keyPair, degree);
    //     std::cout << "Done." << std::endl;
    // }

    // for (int degree: degrees) {
    //     std::cout << "\n############################## DEGREE " << degree << " ##############################" << std::endl;
        
    //     Plaintext result;
    //     cc->Decrypt(keyPair.secretKey, eval(cc, ct, degree), &result);
    //     result->SetLength(inputVector.size());
        
    //     resultPlain = evalPlain(degree);
    //     sigmoid = sigmoidVec();

    //     finalResult = result->GetCKKSPackedValue();

    //     printResults(sigmoid, resultPlain, finalResult);
    // }
    
    return 0;
}