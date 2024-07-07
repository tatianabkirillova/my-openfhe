#include "openfhe.h"
#include "stdio.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

std::vector<double> coeff({ 0.5000000000000107, 0.17209906934813146, 0.0, -0.0029501761301167426, 0.0, 2.6262363172485713e-05, 0.0, -1.1845866975589415e-07, 0.0, 2.801559311285922e-10, 0.0, -3.3145939768213955e-13, 0.0, 1.546695810026845e-16}); //This gives 96.60 (96.5955) accuracy 
std::vector<double> inputVector = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};

uint32_t scaleModSize = 50;
uint32_t batchSize = 8;
uint32_t multDepth = 4;

CryptoContext<DCRTPoly> getCryptoContext() {
    // Step 1: Set CryptoContext
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    std::cout << "CKKS scheme is using ring dimension " << cryptoContext->GetRingDimension() << std::endl << std::endl;

    return cryptoContext;
}

auto getKeyPair(CryptoContext<DCRTPoly> cryptoContext) {
    // Step 2: Key Generation

    // Generate a public/private key pair
    auto keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
 
    return keyPair;
}


auto eval(CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keyPair)
{   
    // Plaintext vector is encoded
    Plaintext ptEncoded = cryptoContext->MakeCKKSPackedPlaintext(inputVector);
    std::cout << "Plaintext: " << ptEncoded << std::endl;

    // The encoded vectors are encrypted
    auto ct = cryptoContext->Encrypt(keyPair.publicKey, ptEncoded);

    auto c_x1 = ct;
    auto c_x2 = cryptoContext->EvalMult(c_x1,c_x1);
    auto c_x3 = cryptoContext->EvalMult(c_x1,c_x2);
    auto c_x4 = cryptoContext->EvalMult(c_x2,c_x2);
    auto c_x5 = cryptoContext->EvalMult(c_x2,c_x3);
    
    auto g_t=cryptoContext->EvalMult(cryptoContext->EvalMult(c_x1,(double)(1.0e-03)),c_x1);//2
    auto g_t1=cryptoContext->EvalMult(cryptoContext->EvalMult(c_x1,(double)(coeff[9]*pow(10,6))),c_x1);//2

    auto g_t2=cryptoContext-> EvalSquare(g_t);//3 x^4
    auto g_t3=cryptoContext->EvalMult(g_t1,c_x3);//3 x^5
    
    auto e_t=cryptoContext->EvalMult(cryptoContext->EvalMult(c_x1,(double)(1.0e-05)),c_x2);//2
    auto e_t1=cryptoContext->EvalMult(cryptoContext->EvalMult(c_x1,(double)(coeff[11]*pow(10,10))),c_x1);//2

    auto e_t2=cryptoContext-> EvalSquare(e_t);//3 x^6
    auto e_t3=cryptoContext->EvalMult(e_t1,c_x3);//3 x^5
    
    
    auto f_t=cryptoContext->EvalMult(cryptoContext->EvalMult(c_x1,(double)(1.0e-06)),c_x2);//2
    auto f_t1=cryptoContext->EvalMult(cryptoContext->EvalMult(c_x1,(double)(coeff[13]*pow(10,12))),c_x2);//2

    auto f_t2=cryptoContext-> EvalSquare(f_t);//3 x^6
    auto f_t3=cryptoContext->EvalMult(f_t1,c_x4);//3 x^7
    
    
    auto eval_1 = cryptoContext->EvalAdd(cryptoContext->EvalMult(c_x1,coeff[1]),coeff[0]);
    auto eval_2 = cryptoContext->EvalAdd(cryptoContext->EvalMult(cryptoContext->EvalMult(c_x2,coeff[3]),c_x1),eval_1);

    auto eval_3 = cryptoContext->EvalAdd(cryptoContext->EvalMult(cryptoContext->EvalMult(c_x3,coeff[5]),c_x2),eval_2);
    auto eval_4 = cryptoContext->EvalAdd(cryptoContext->EvalMult(cryptoContext->EvalMult(c_x4,coeff[7]),c_x3),eval_3);
    auto eval_5 = cryptoContext->EvalAdd(cryptoContext->EvalMult(g_t2,g_t3),eval_4);
    auto eval_6 = cryptoContext->EvalAdd(cryptoContext->EvalMult(e_t2,e_t3),eval_5);
    auto eval_7 = cryptoContext->EvalAdd(cryptoContext->EvalMult(f_t2,f_t3),eval_6);
    
    //Step 5: Decryption

    // Decrypt the result of additions
    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, eval_7, &result);
    result->SetLength(inputVector.size());

    return result;
}

int main() {
    CryptoContext<DCRTPoly> cryptoContext = getCryptoContext();
    auto keyPair = getKeyPair(cryptoContext);

    Plaintext result = eval(cryptoContext, keyPair);
    std::cout << "\nExpected: (0.5621765, 0.6224593, 0.6791787, 0.7310585, 0.8807970, 0.9525741, 0.9525741, 0.9933071)" << std::endl;
    std::cout << "\nResult: " << result << std::endl;

    return 0;
}