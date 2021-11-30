#include "palisade.h"

using namespace lbcrypto;

int main() {
  // Step 1 - Set CryptoContext

  // Setting the main parameters
  int plaintextModulus = 65537;
  double stdDeviation = 3.2;
  SecurityLevel securityLevelType = HEStd_128_classic;
  uint32_t depth = 5;

  // Instantiating the crypto context, where the last two parameters are key refresh type and modulus switching type.
  CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevelType, stdDeviation, depth, OPTIMIZED, BV);

  // Enabling features that I wish to use
  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);
  cryptoContext->Enable(LEVELEDSHE);

  // Step 2 - Key Generation

  // Initializing Public Key Containers
  LPKeyPair<DCRTPoly> keyPair;

  // Generating a public/private key pair
  keyPair = cryptoContext->KeyGen();

  // Generating the relinearization key
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  // Step 3 - Encryption

  // beta0 is encoded
  std::vector<int64_t> beta0 = {-3};
  Plaintext plaintextbeta0 = cryptoContext->MakePackedPlaintext(beta0);
  // beta1 vector is encoded
  std::vector<int64_t> beta11 = {7};
  Plaintext plaintextbeta11 = cryptoContext->MakePackedPlaintext(beta11);
  std::vector<int64_t> beta12 = {6};
  Plaintext plaintextbeta12 = cryptoContext->MakePackedPlaintext(beta12);
  std::vector<int64_t> beta13 = {-7};
  Plaintext plaintextbeta13 = cryptoContext->MakePackedPlaintext(beta13);
  std::vector<int64_t> beta14 = {-6};
  Plaintext plaintextbeta14 = cryptoContext->MakePackedPlaintext(beta14);
  std::vector<int64_t> beta15 = {2};
  Plaintext plaintextbeta15 = cryptoContext->MakePackedPlaintext(beta15);
  std::vector<int64_t> beta16 = {5};
  Plaintext plaintextbeta16 = cryptoContext->MakePackedPlaintext(beta16);
  std::vector<int64_t> beta17 = {9};
  Plaintext plaintextbeta17 = cryptoContext->MakePackedPlaintext(beta17);
  std::vector<int64_t> beta18 = {1};
  Plaintext plaintextbeta18 = cryptoContext->MakePackedPlaintext(beta18);
  // xvector vector is encoded
  std::vector<int64_t> xvector1 = {5};
  Plaintext plaintextxvector1 = cryptoContext->MakePackedPlaintext(xvector1);
  std::vector<int64_t> xvector2 = {10};
  Plaintext plaintextxvector2 =cryptoContext->MakePackedPlaintext(xvector2);
  std::vector<int64_t> xvector3 = {5};
  Plaintext plaintextxvector3 = cryptoContext->MakePackedPlaintext(xvector3);
  std::vector<int64_t> xvector4 = {-5};
  Plaintext plaintextxvector4 = cryptoContext->MakePackedPlaintext(xvector4);
  std::vector<int64_t> xvector5 = {-2};
  Plaintext plaintextxvector5 = cryptoContext->MakePackedPlaintext(xvector5);
  std::vector<int64_t> xvector6 = {9};
  Plaintext plaintextxvector6 = cryptoContext->MakePackedPlaintext(xvector6);
  std::vector<int64_t> xvector7 = {1};
  Plaintext plaintextxvector7 = cryptoContext->MakePackedPlaintext(xvector7);
  std::vector<int64_t> xvector8 = {3};
  Plaintext plaintextxvector8 = cryptoContext->MakePackedPlaintext(xvector8);


  // The encoded vectors are encrypted
  auto ciphertextbeta0 = cryptoContext->Encrypt(keyPair.publicKey, plaintextbeta0);
  auto ciphertextbeta1_1 = cryptoContext->Encrypt(keyPair.publicKey, plaintextbeta11);
  auto ciphertextbeta1_2 = cryptoContext->Encrypt(keyPair.publicKey,plaintextbeta12);
  auto ciphertextbeta1_3 = cryptoContext->Encrypt(keyPair.publicKey,plaintextbeta13);
  auto ciphertextbeta1_4 = cryptoContext->Encrypt(keyPair.publicKey,plaintextbeta14);
  auto ciphertextbeta1_5 = cryptoContext->Encrypt(keyPair.publicKey,plaintextbeta15);
  auto ciphertextbeta1_6 = cryptoContext->Encrypt(keyPair.publicKey,plaintextbeta16);
  auto ciphertextbeta1_7 = cryptoContext->Encrypt(keyPair.publicKey,plaintextbeta17);
  auto ciphertextbeta1_8 = cryptoContext->Encrypt(keyPair.publicKey,plaintextbeta18);
  auto ciphertextxvector_1 = cryptoContext->Encrypt(keyPair.publicKey, plaintextxvector1);
  auto ciphertextxvector_2 = cryptoContext->Encrypt(keyPair.publicKey,plaintextxvector2);
  auto ciphertextxvector_3 = cryptoContext->Encrypt(keyPair.publicKey,plaintextxvector3);
  auto ciphertextxvector_4 = cryptoContext->Encrypt(keyPair.publicKey,plaintextxvector4);
  auto ciphertextxvector_5 = cryptoContext->Encrypt(keyPair.publicKey,plaintextxvector5);
  auto ciphertextxvector_6 = cryptoContext->Encrypt(keyPair.publicKey,plaintextxvector6);
  auto ciphertextxvector_7 = cryptoContext->Encrypt(keyPair.publicKey,plaintextxvector7);
  auto ciphertextxvector_8 = cryptoContext->Encrypt(keyPair.publicKey,plaintextxvector8);

  // Step 4 - Evaluation of the circuit

  // Inner product of dimension 8
  // multiply together pairwise, this adds 1 level evenly across everything
  auto ciphertextPairwiseMult_1 = cryptoContext->EvalMult(ciphertextbeta1_1,ciphertextxvector_1);
  auto ciphertextPairwiseMult_2 = cryptoContext->EvalMult(ciphertextbeta1_2,ciphertextxvector_2);
  auto ciphertextPairwiseMult_3 = cryptoContext->EvalMult(ciphertextbeta1_3,ciphertextxvector_3);
  auto ciphertextPairwiseMult_4 = cryptoContext->EvalMult(ciphertextbeta1_4,ciphertextxvector_4);
  auto ciphertextPairwiseMult_5 = cryptoContext->EvalMult(ciphertextbeta1_5,ciphertextxvector_5);
  auto ciphertextPairwiseMult_6 = cryptoContext->EvalMult(ciphertextbeta1_6,ciphertextxvector_6);
  auto ciphertextPairwiseMult_7 = cryptoContext->EvalMult(ciphertextbeta1_7,ciphertextxvector_7);
  auto ciphertextPairwiseMult_8 = cryptoContext->EvalMult(ciphertextbeta1_8,ciphertextxvector_8);

  // Sum pairwise in a tree like structure, this adds floor of log n levels
  auto ciphertextSummed1 = cryptoContext->EvalAdd(ciphertextPairwiseMult_1, ciphertextPairwiseMult_2);
  auto ciphertextSummed2 = cryptoContext->EvalAdd(ciphertextPairwiseMult_3, ciphertextPairwiseMult_4);
  auto ciphertextSummed3 = cryptoContext->EvalAdd(ciphertextPairwiseMult_5, ciphertextPairwiseMult_6);
  auto ciphertextSummed4 = cryptoContext->EvalAdd(ciphertextPairwiseMult_7, ciphertextPairwiseMult_8);

  auto ciphertextSummed1_1 = cryptoContext->EvalAdd(ciphertextSummed1, ciphertextSummed2);
  auto ciphertextSummed1_2 = cryptoContext->EvalAdd(ciphertextSummed3, ciphertextSummed4);

  auto ciphertextSummed = cryptoContext->EvalAdd(ciphertextSummed1_1, ciphertextSummed1_2);

  // Add the constant term, this adds 1 level total
  auto ciphertextAddedBeta0 = cryptoContext->EvalAdd(ciphertextbeta0, ciphertextSummed);

  // Step 5 - Decryption

  // Decrypt the result of the circuit Evaluation
  Plaintext plaintextCircuit;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddedBeta0,&plaintextCircuit);

  // Output results
  std::cout << "\nResult of encrypted circuit:" << std::endl;
  std::cout << "#beta0 + beta1*x = " << plaintextCircuit << std::endl;


  return 0;
}
