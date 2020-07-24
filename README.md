# cppaillier
Paillier homomorphic encryption implemented in C++. Including some ZKPs.

# What is Paillier cryptosystem?

Paillier cryptosystem is a homomorphic cryptosystem based on the [DCRA asumption](https://en.wikipedia.org/wiki/Decisional_composite_residuosity_assumption).

It provides roughly the same security as the commonly used RSA cryptosystem at the cost of larger ciphertext size (ciphertext has twice as many bits as the plaintext). It provides replay-attack resistance out of the box since a plaintext maps to many ciphertexts.

A Paillier ciphertext is calculated like this: $$Enc(m)=g^mr^n\mod n^2$$.

Where:

* $g$ is a cyclic group generator (integer between $0$ and $n^2$).
* $m​$ is the plaintext.
* $r$ is a random number between $0$ and $n​$.
* $n$ is a RSA modulus (product of two primes of roughly the same bit size).



Like all homomorphic cryptosystems there is a set of functions that can be computed on ciphertexts. In the case of this library there are:

1. Addition of two ciphertexts
2. Addition of ciphertext and plaintext
3. Subtraction of two ciphertexts
4. Multiplication of ciphertext and plaintext



There are also some zero knowledge proofs:

1. Zero Knowledge Proof of Set Membership: prove that a given ciphertext is the encryption of a value from a given set of plaintexts.
2. Zero Knowledge Proof of Correct Decryption: prove that a given plaintext comes from a given ciphertext without revealing the private key and without allowing third parties to replay the proof (this is an interactive proof and requires input from the verifier).



Last but not least it also provides methods to cryptographically sign/verify messages.



## How to build

1. Install gmp library if you don't have it already https://gmplib.org
2. Install mppp https://github.com/bluescarni/mppp
3. Install nlohmann json (required for key serialization) https://github.com/nlohmann/json
4. ```bash
    git clone https://github.com/kran6a/cppaillier
    ```
5. ```bash
    cd cppaillier
    ```
6. ```bash
    cmake .
    ```
7. ```bash
    make
    ```
8. ```bash
    ./paillier_test
    ```
