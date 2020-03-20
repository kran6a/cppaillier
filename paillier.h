//
// Created by kranga on 12/11/19.
//

#ifndef PAILLIER_PAILLIER_H
#define PAILLIER_PAILLIER_H

#include <mp++/mp++.hpp>
#include <nlohmann/json.hpp>
#include "./utils.h"
using json = nlohmann::json;
using int_t = mppp::integer<64>;    //96  = 3072/64
using t = mppp::integer<1>;
class PaillierPublicKey {
private:
    [[nodiscard]] int_t randomR() const;
public:
    static constexpr unsigned short const DEFAULT_KEYSIZE = 3072;
    unsigned short keysize = 0;
    int_t n;
    int_t g;
    int_t _n2;
    explicit PaillierPublicKey(const std::string &n);                           //Carga desde archivo
    explicit PaillierPublicKey(const int_t &n);                                 //Copia
    PaillierPublicKey() = default;
    [[nodiscard]] int_t encrypt(const int_t &cleartext, const int_t &r = int_t{0}) const;
    [[nodiscard]] std::pair<const int_t, const int_t> rEncrypt(const int_t &cleartext) const;  //Para las ZKP
    [[nodiscard]] static int_t add(const int_t &enc_n, const int_t &enc_m, const PaillierPublicKey &pk);
    [[nodiscard]] int_t add(const int_t &enc_n, const int_t &enc_m) const;
    [[nodiscard]] int_t raw_add(const int_t &enc_n, const int_t &raw_m) const;
    [[nodiscard]] static int_t sub(const int_t &enc_n, const int_t &enc_m, const PaillierPublicKey &pk);
    [[nodiscard]] int_t sub(const int_t &enc_n, const int_t &enc_m) const;
    [[nodiscard]] static int_t mul(const int_t &enc_n, const int_t &raw_m, const PaillierPublicKey &pk);
    [[nodiscard]] int_t mul(const int_t &enc_n, const int_t &raw_m) const;
    [[nodiscard]] bool verifySignature(const int_t &message, const std::pair<int_t, int_t> &signature) const;
    [[nodiscard]] std::pair<const int_t, std::vector<std::vector<int_t>>> encryptWithZKPSet(const int_t &message, const std::vector<int_t> &validMessages, unsigned int bits=256) const;
    [[nodiscard]] bool ZKPInSet(const int_t &ciphertext, const std::vector<int_t> &as, const std::vector<int_t> &es, const std::vector<int_t> &zs, const std::vector<int_t> &validMessages, unsigned int bits=256) const;
    [[nodiscard]] inline bool ZKPInSet(const int_t &ciphertext, std::vector<std::vector<int_t>> proof, const std::vector<int_t> &validMessages, unsigned int bits=256) const{
        if (proof.size() != 3)
            return false;
        return this->ZKPInSet(ciphertext, proof[0], proof[1], proof[2], validMessages, bits);
    };
    [[nodiscard]] json to_json() const;
    [[nodiscard]] std::string to_string() const;
};
class [[nodiscard]] PaillierPrivateKey{
private:
    PaillierPublicKey pk{};
    int_t p,q,_p2,_hp,_q2,_hq,p_inverse,n,g,_n2;
    [[nodiscard]] int_t crt(const int_t &n, const int_t &m) const;
public:
    PaillierPrivateKey(const int_t &p, const int_t &q);
    PaillierPrivateKey() = default;
    [[nodiscard]] static std::pair<const PaillierPublicKey, const PaillierPrivateKey> generateKeypair(unsigned short keysize = PaillierPublicKey::DEFAULT_KEYSIZE);
    [[nodiscard]] PaillierPublicKey getPublicKey() const;
    [[nodiscard]] int_t decrypt(const int_t &ciphertext) const;
    [[nodiscard]] std::pair<const int_t, const int_t> sign(const int_t &message) const;
    [[nodiscard]] static int_t L_function(const int_t &n, const int_t &p);
    [[nodiscard]] static int_t H_function(const int_t &n, const int_t &n2, const int_t &g);
    [[nodiscard]] int_t computeR(const int_t &ciphertext) const;
    [[nodiscard]] json to_json() const;
    [[nodiscard]] bool ZKPCorrectDecryption(const int_t &ciphtext, const int_t &VerifierRandomValue) const;
    [[nodiscard]] bool ZKPCorrectDecryption(const int_t &ciphertext, const int_t &obtainedPlaintext, const int_t &VerifierRandomValue) const;
    [[nodiscard]] std::string to_string() const;
};
#endif //PAILLIER_PAILLIER_H
