#include <iostream>
#include "paillier.cpp"
static PaillierPrivateKey p = PaillierPrivateKey::generateKeypair().second;
void ZKPInSetTest(){
    std::vector<int_t> validMessages = {int_t{10}, int_t{100}, int_t{1000}, int_t{10000}, int_t{32}};
    std::cout << "Testing whether the encryption of 100 is in the array [10, 100, 1000, 10000, 32]\n";
    std::pair<int_t, std::vector<std::vector<int_t>>> cproof = p.getPublicKey().encryptWithZKPSet(int_t{32}, validMessages);
    if (p.getPublicKey().ZKPInSet(cproof.first, cproof.second.at(0), cproof.second.at(1), cproof.second.at(2), validMessages))
        std::cout << "True\n";
    else
        std::cout << "False\n";
    cproof = p.getPublicKey().encryptWithZKPSet(int_t{42}, validMessages);
    std::cout << "Testing whether the encryption of 42 is in the array [10, 100, 1000, 10000, 32]\n";
    if (p.getPublicKey().ZKPInSet(cproof.first, cproof.second.at(0), cproof.second.at(1), cproof.second.at(2), validMessages))
        std::cout << "True\n";
    else
        std::cout << "False\n";
}
void genericTest(){
    std::cout << "Encryption of 123: " << p.getPublicKey().encrypt(int_t{123}) << "\n";
    std::cout << "Decryption of (#123+#123): " << p.decrypt(PaillierPublicKey::add(p.getPublicKey().encrypt(int_t{123}),p.getPublicKey().encrypt(int_t{123}), p.getPublicKey())) << "\n";
    std::cout << "Decryption of (#123-#123): " << p.decrypt(PaillierPublicKey::sub(p.getPublicKey().encrypt(int_t{123}), p.getPublicKey().encrypt(int_t{123}), p.getPublicKey())) << "\n";
    std::cout << "Decryption of (#123+1): " << p.decrypt(p.getPublicKey().raw_add(p.getPublicKey().encrypt(int_t{123}), int_t{1})) << "\n";
    std::cout << "Decryption of (#123·4): " << p.decrypt(PaillierPublicKey::mul(p.getPublicKey().encrypt(int_t{123}), int_t{4}, p.getPublicKey())) << "\n";
    std::cout << "Public key in JSON format:\n" << p.getPublicKey().to_string() << "\n";
    std::cout << "Private key in JSON format:\n" << p.to_string() << "\n";
    const std::pair<int_t, int_t> signature = p.sign(int_t{333});
    std::cout << "Verifying signature (must return True):\n" << (p.getPublicKey().verifySignature(int_t{333}, signature)?"True":"False") << "\n";
}
void ZKPCorrectDecryptionTest(){
    std::cout << "Testing whether (#555-#555) is an encryption of 0 (must return True):\n" << (p.ZKPCorrectDecryption(p.getPublicKey().encrypt(int_t{555}), int_t{555},getRandomNumber(PaillierPublicKey::DEFAULT_KEYSIZE-1))?"True":"False") << "\n";
    std::cout << "Testing whether (#555-#554) is an encryption of 0 (must return False):\n" << (p.ZKPCorrectDecryption(p.getPublicKey().encrypt(int_t{555}), int_t{554},getRandomNumber(PaillierPublicKey::DEFAULT_KEYSIZE-1))?"True":"False") << "\n";
}
int main(){
    std::ios_base::sync_with_stdio(false);
    genericTest();
    ZKPInSetTest();
    ZKPCorrectDecryptionTest();
}
