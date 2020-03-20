//
// Created by kranga on 12/11/19.
//

#ifndef PAILLIER_UTILS_H
#define PAILLIER_UTILS_H
#include <mp++/mp++.hpp>
#include <gmpxx.h>
#include <random>
#include <algorithm>
#include <bitset>
#include "./sha256.h"
using int_t = mppp::integer<64>;    //96  = 3072*2/64
template <class Cont, class Lamb>
inline void forEach(const Cont &c, const Lamb &fun){
    std::for_each(c.begin(), c.end(), fun);
}
inline int_t lcm(const int_t &a, const int_t &b){
    int_t ret;
    mpz_lcm(ret.get_mpz_t(), a.get_mpz_view(), b.get_mpz_view());
    return ret;
}
[[nodiscard]] inline int_t gcd(const int_t &a, const int_t &b){
    int_t ret;
    mpz_gcd (ret.get_mpz_t(), a.get_mpz_view(), b.get_mpz_view());
    return ret;
}
template <class Cont, class Lamb>
[[nodiscard]] auto map(const Cont &c, const Lamb &fun){
    std::vector<typename std::result_of<Lamb(const typename Cont::value_type&)>::type> ret;
    ret.reserve(c.size());
    for (const auto &i : c)
        ret.emplace_back(fun(i));
    return ret;
}
template <class Cont, class Lamb, class Init>
[[nodiscard]] inline Init reduce(const Cont &c, const Lamb &fun, const Init &initialValue){
    Init ret = initialValue;
    for (const auto &i : c)
        ret=fun(ret, i);
    return ret;
}
template <class Cont, class Lamb>
[[nodiscard]] inline bool every(const Cont &c, const Lamb &fun){
    return std::all_of(c.cbegin(), c.cend(), fun);
}
template <typename Cont, typename Lamb>
[[nodiscard]] Cont filter(const Cont &c, const Lamb &fun) {
    Cont result;
    std::copy_if(c.begin(), c.end(), std::back_inserter(result), fun);
    return result;
}
template <typename Cont, typename Cont2>
[[nodiscard]] auto zip(const Cont &av, const Cont2 &bv) {
    using t1 = typename Cont::value_type;
    using t2 = typename Cont2::value_type;
    std::unordered_map<t1, t2> ret{av.size()};
    std::transform(av.begin(), av.end(), bv.begin(), std::inserter(ret, ret.end()), [](const t1 &a, const t2 &b) {
        return std::make_pair(a, b);
    });
    return ret;
}
std::string inline sha256(const std::string &input){
    std::string ret;
    ret.reserve(64);
    picosha2::hash256_hex_string(input, ret);
    return ret;
}
template <class Cont>
[[nodiscard]] std::string inline join(const Cont &c, const std::string_view &separator = ""){
    std::string ret;
    ret.reserve(c.size()+c.size()*separator.size());
    for (const auto &i : c)
        ret+=i.to_string()+separator.data();
    return ret;
}
[[nodiscard]] inline int_t powm(const int_t &base, const int_t &exp, const int_t &mod){
    int_t ret;
    mpz_powm(ret.get_mpz_t(), base.get_mpz_view(), exp.get_mpz_view(), mod.get_mpz_view());
    return ret;
}
[[nodiscard]] inline int_t invertm(const int_t &n, const int_t &mod) {
    int_t ret;
    mpz_invert(ret.get_mpz_t(), n.get_mpz_view(), mod.get_mpz_view());
    return ret;
}
[[nodiscard]] inline int_t getRandomNumber(const unsigned short bitsize){
    mpz_class ran;
    gmp_randclass rr(gmp_randinit_default);
    std::random_device r{};
    std::seed_seq seed_seq{r(), r(), r(), r(), r(), r(), r(), r()};
    std::mt19937 engine{seed_seq};
    rr.seed(engine());
    ran = rr.get_z_bits(bitsize);
    return int_t{ran.get_mpz_t()};
}
[[nodiscard]] inline int_t ior(const int_t &n1, const int_t &n2){
    int_t ret;
    mpz_ior(ret.get_mpz_t(), n1.get_mpz_view(), n2.get_mpz_view());
    return ret;
}
[[nodiscard]] inline int_t getCoprime(int_t target){
    while (true) {
        const unsigned short bits = mpz_sizeinbase(target.get_mpz_view(), 2);
        const int_t lowerBound = pow(int_t{2},bits-1)+1;
        const int_t size = pow(int_t{2}, bits) - lowerBound;
        int_t possible = ior(lowerBound+(getRandomNumber(bits)), int_t{1});
        const int_t result = possible;
        if (possible > (pow(int_t{2}, 1024)))
            return result;
        while(target != 0) {
            int_t tmp = possible;
            possible = target;
            target = tmp%target;
        }
        if (possible == int_t{1})
            return result;
    }
}
template <class T = unsigned long int, size_t ST = sizeof(T)*8>
constexpr inline std::bitset<ST>toBinary(const T &value) {
    return std::bitset<ST>(value);
}
inline bool isProbablyPrime(const int_t &n, unsigned short rounds = 50){
    return mpz_probab_prime_p(n.get_mpz_view(), rounds); //Devuelve 2 si es 100% primo, 1 si es probablemente primo y 0 si no lo es
}
template <class T = unsigned long int>
constexpr T fromBinary(const std::bitset<sizeof(T)*8> &bs){
    return static_cast<T>(bs.to_ulong());
}
[[nodiscard]] constexpr unsigned int str2int(const char* str, int h = 0){
    return !str[h] ? 5381 : (str2int(str, h+1) * 33) ^ str[h];
}

#endif //PAILLIER_UTILS_H
