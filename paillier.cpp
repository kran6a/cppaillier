//
// Created by kranga on 12/11/19.
//

#include "./paillier.h"
int_t PaillierPublicKey::randomR() const{
    int_t ret;
    do {
        ret = getRandomNumber(mpz_sizeinbase(this->n.get_mpz_view(), 2));
    } while (ret == 0 || ret >= this->n);
    return ret;
}
std::pair<const int_t, const int_t> PaillierPublicKey::rEncrypt(const int_t &cleartext) const{
    std::pair<int_t, int_t> ret;
    ret.first = randomR();
    ret.second = this->encrypt(cleartext, ret.first);
    return ret;
}
std::pair<const int_t, std::vector<std::vector<int_t>>> PaillierPublicKey::encryptWithZKPSet(const int_t &message, const std::vector<int_t> &validMessages, unsigned int bits) const {
    std::vector<int_t> as;
    std::vector<int_t> es;
    std::vector<int_t> zs;
    as.reserve(validMessages.size());
    es.reserve(validMessages.size());
    zs.reserve(validMessages.size());
    std::pair<const int_t, const int_t> rcipher = this->rEncrypt(message);
    const int_t om = getCoprime(this->n);
    const int_t ap = powm(om, this->n, this->_n2);
    long long int mi = -1;
    long long int i = 0;
    forEach(validMessages, [&as, &zs, &es, &i, this, &rcipher, &ap, &message, &mi, bits](const int_t &mk) {
        const int_t gmk = powm(this->g, mk, this->_n2);
        const int_t uk = rcipher.second * invertm(gmk, this->_n2) % this->_n2;
        if (message != mk) {
            const int_t zk = getCoprime(this->n);
            int_t ek;
            do {
                ek = getRandomNumber(bits);
            } while (ek <= 2 or ek >= pow(int_t{2}, bits));
            const int_t zn = powm(zk, this->n, this->_n2);
            const int_t ue = powm(uk, ek, this->_n2);
            const int_t ak = (zn * invertm(ue, this->_n2)) % this->_n2;
            as.emplace_back(ak);
            zs.emplace_back(zk);
            es.emplace_back(ek);
        } else {
            as.emplace_back(ap);
            zs.emplace_back(int_t{0});   //Solo para mantener los arrays paralelos
            es.emplace_back(int_t{0});   //Solo para mantener los arrays paralelos
            mi = i;
        }
        ++i;
    });
    const std::string hash = sha256(join(as));
    const int_t esum = reduce(filter(es, [](const int_t &num) { return num != 0; }), [bits](auto acc, const auto &ek) -> int_t { return (acc + ek) % pow(int_t{2}, bits); },int_t{0});
    const int_t ep = (int_t{hash, 16} - esum) % pow(int_t{2}, bits);
    const int_t rep = powm(rcipher.first, ep, this->n);
    const int_t zp = om * rep % this->n;
    if (mi != -1){                          //if the message is not in the set -> mi = -1
        es[mi] = ep;
        zs[mi] = zp;
    }
    std::vector<std::vector<int_t>> proof{as, es, zs};
    return std::pair<const int_t, std::vector<std::vector<int_t>>> {rcipher.second, proof};
}
bool PaillierPublicKey::ZKPInSet(const int_t &ciphertext, const std::vector<int_t> &as, const std::vector<int_t> &es, const std::vector<int_t> &zs, const std::vector<int_t> &validMessages, unsigned int bits) const{
    std::string hash = sha256(join(as));
    std::vector<int_t> us = map(validMessages, [&ciphertext, this](const int_t &mk){
        const int_t gmk = powm(this->g, mk, this->_n2);
        const int_t uk = ciphertext * invertm(gmk, this->_n2) % this->_n2;
        return uk;
    });

    const int_t esum = reduce(es, [bits](auto acc, const auto &ek)->int_t{return (acc+ek) % pow(int_t{2}, bits);}, int_t{0});
    if (int_t{hash, 16} != esum)
        return false;
    unsigned long long int i = 0;
    return every(zs,[&as, &es, &us, &i, this](const int_t &zk){
        const int_t ak = as[i];
        const int_t ek = es[i];
        const int_t uk = us[i];
        ++i;
        const int_t zkn = powm(zk, this->n, this->_n2);
        const int_t uke = powm(uk, ek, this->_n2);
        const int_t akue = ak * uke % this->_n2;
        return zkn == akue;
    });
}

std::string PaillierPrivateKey::to_string() const{
    return this->to_json().dump();
}
std::string PaillierPublicKey::to_string() const{
    return this->to_json().dump();
}
json PaillierPublicKey::to_json() const{
    return json{
            {"n", this->n.to_string()},
            {"n2", this->_n2.to_string()},
            {"g", this->g.to_string()}
    };
}
json PaillierPrivateKey::to_json() const{
    return json{
            {"p", this->p.to_string() },
            {"q", this->q.to_string() },
            {"publicKey", this->getPublicKey().to_json()}
    };
}
PaillierPublicKey::PaillierPublicKey(const std::string &n){
    this->n = int_t{n};
    this->_n2 = pow(this->n,2);
    this->g = this->n+1;
    this->keysize = mpz_sizeinbase(this->n.get_mpz_view(), 2);
}
PaillierPublicKey::PaillierPublicKey(const int_t &n){
    this->n = n;
    this->g = this->n+1;
    this->_n2 = pow(this->n,2);
    this->keysize = mpz_sizeinbase(this->n.get_mpz_view(), 2);
}
std::pair<const PaillierPublicKey, const PaillierPrivateKey> PaillierPrivateKey::generateKeypair(unsigned short keysize){
    std::pair<PaillierPublicKey, PaillierPrivateKey> ret = std::pair<PaillierPublicKey, PaillierPrivateKey>();
    ret.first = PaillierPublicKey();
    do {
        const int_t p = mppp::nextprime(getRandomNumber(mpz_sizeinbase(int_t{pow(int_t{2}, keysize / 2)}.get_mpz_view(), 2)-1));
        int_t q = p;
        while (q == p)
            q = mppp::nextprime(getRandomNumber(mpz_sizeinbase(int_t{pow(int_t{2}, keysize / 2)}.get_mpz_view(), 2)-1));
        ret = {PaillierPublicKey(p * q), PaillierPrivateKey(p, q)};
    } while(ret.first.keysize != keysize);
    return ret;
}
int_t PaillierPrivateKey::crt(const int_t &mp, const int_t &mq) const{
    const int_t u = (mq-mp) * this->p_inverse % this->q;
    return mp+(u*this->p);
}
int_t PaillierPublicKey::encrypt(const int_t &cleartext, const int_t &r) const{
    const int_t rr = r == 0 ? randomR(): r;
    const int_t nude_ciphertext = (this->n * cleartext + 1) % this->_n2;
    const int_t obfuscator = powm(rr, this->n, this->_n2);
    return (nude_ciphertext * obfuscator) % this->_n2;
}
int_t PaillierPublicKey::add(const int_t &enc_n, const int_t &enc_m, const PaillierPublicKey &pk) {
    return enc_n * enc_m % pk._n2;
}
int_t PaillierPublicKey::add(const int_t &enc_n, const int_t &enc_m) const{
    return PaillierPublicKey::add(enc_n, enc_m, *this);
}
int_t PaillierPublicKey::mul(const int_t &enc_n, const int_t &raw_m, const PaillierPublicKey &pk) {
    return powm(enc_n, raw_m, pk._n2);
}
int_t PaillierPublicKey::mul(const int_t &enc_n, const int_t &raw_m) const{
    return PaillierPublicKey::mul(enc_n, raw_m, *this);
}

int_t PaillierPublicKey::raw_add(const int_t &enc_n, const int_t &raw_m) const{
    return enc_n * powm(this->g, raw_m, this->_n2) % this->_n2;
}
bool PaillierPublicKey::verifySignature(const int_t &message, const std::pair<int_t, int_t> &signature) const{
    const int_t hash = int_t{sha256(message.to_string()), 16} % this->_n2; // %n2 es necesario sólo si el tamaño en bits del hash es mayor que el tamaño de n2. Usar una implementación modificada de sha3 solucionaría el problema y mejoraría la seguridad para cualquier tamaño de clave
    const int_t a = powm(this->g, signature.first, this->_n2);
    const int_t b = powm(signature.second, this->n, this->_n2);
    const int_t sighash = a * b % this->_n2;
    return hash == sighash;
}
int_t PaillierPublicKey::sub(const int_t &enc_n, const int_t &enc_m, const PaillierPublicKey &pk) {
    return enc_n*invertm(enc_m, pk._n2) % pk._n2;
}
int_t PaillierPublicKey::sub(const int_t &enc_n, const int_t &enc_m) const {
    return PaillierPublicKey::sub(enc_n, enc_m, *this);
}

int_t PaillierPrivateKey::L_function(const int_t &n, const int_t &p){
    return (n-1)/p;
}
int_t PaillierPrivateKey::H_function(const int_t &x, const int_t &x2, const int_t &g) {
    return invertm(PaillierPrivateKey::L_function(powm(g, x - 1, x2), x), x);
}
PaillierPrivateKey::PaillierPrivateKey(const int_t& p, const int_t &q){
    this->p = p;
    this->_p2 = pow(p,2);
    this->q = q;
    this->_q2 = pow(this->q,2);
    this->n = this->p*this->q;
    this->_n2 = pow(this->n, 2);
    this->g = this->n+1;
    this->pk = PaillierPublicKey(this->n);
    this->p_inverse = invertm(this->p, this->q);
    this->_hq = PaillierPrivateKey::H_function(this->q, this->_q2, this->g);
    this->_hp = PaillierPrivateKey::H_function(this->p, this->_p2, this->g);
}
int_t PaillierPrivateKey::decrypt(const int_t &ciphertext) const{
    const int_t decrypt_to_p = PaillierPrivateKey::L_function(powm(ciphertext, this->p-1, this->_p2), this->p) * this->_hp % this->p;
    const int_t decrypt_to_q = PaillierPrivateKey::L_function(powm(ciphertext, this->q-1, this->_q2), this->q) * this->_hq % this->q;
    const int_t ret = this->crt(decrypt_to_p, decrypt_to_q);
    return ret;
}
PaillierPublicKey PaillierPrivateKey::getPublicKey() const{
    return this->pk;
}

std::pair<const int_t, const int_t> PaillierPrivateKey::sign(const int_t &message) const{
    const int_t hash = int_t{sha256(message.to_string()), 16};
    const int_t lambda = lcm(this->p-1, this->q-1);
    const int_t numerator = (powm(hash, lambda, this->_n2)-1) / this->n;
    const int_t denominator = (powm(this->g, lambda, this->_n2)-1) / this->n;
    const int_t inverse_deno = invertm(denominator, this->n);
    const int_t s1 = numerator * inverse_deno % this->n;
    const int_t inverse_n = invertm(this->n, lambda);
    const int_t inverse_g = invertm(powm(this->g, s1, this->n), this->n);
    const int_t s2 = powm(hash * inverse_g, inverse_n, this->n);
    return std::pair<int_t, int_t>{s1, s2};
}

int_t PaillierPrivateKey::computeR(const int_t &ciphertext) const {
    const int_t M = invertm(this->n, (this->p-1)*(this->q-1));
    return powm(ciphertext, M, this->n);
}
//Verifier value is a random value between 0 and n provided by the verifier, it should not be generated server-side
bool PaillierPrivateKey::ZKPCorrectDecryption(const int_t &ciphtext, const int_t &VerifierRandomValue) const{
    return ZKPCorrectDecryption(ciphtext, this->decrypt(ciphtext), VerifierRandomValue);
}

bool PaillierPrivateKey::ZKPCorrectDecryption(const int_t &ciphtext, const int_t &obtainedPlaintext, const int_t &VerifierRandomValue) const{
    const int_t ciphertext = PaillierPublicKey::sub(ciphtext, this->getPublicKey().encrypt(obtainedPlaintext), this->getPublicKey());
    const std::pair<int_t, int_t> CifradoADemostrar_R = {this->computeR(ciphertext), ciphertext};
    const std::pair<int_t, int_t> ProverEncryptionOf0_R = this->getPublicKey().rEncrypt(int_t{0});
    const int_t ProverZ = powm(CifradoADemostrar_R.first*ProverEncryptionOf0_R.first, VerifierRandomValue, this->getPublicKey().n);

    const int_t VerifierCheck1 = gcd(CifradoADemostrar_R.second, this->getPublicKey().n);
    const int_t VerifierCheck2 = gcd(ProverEncryptionOf0_R.second, this->getPublicKey().n);
    const int_t VerifierCheck3 = gcd(ProverZ, this->getPublicKey().n);
    if (VerifierCheck1 != int_t{1} or VerifierCheck2 != int_t{1} or VerifierCheck3 != int_t{1})
        return false;
    const int_t VerifierLast = this->getPublicKey().encrypt(int_t{0}, ProverZ);
    if (VerifierLast != powm(ProverEncryptionOf0_R.second*CifradoADemostrar_R.second, VerifierRandomValue, this->getPublicKey()._n2))
        return false;
    return true;
}
