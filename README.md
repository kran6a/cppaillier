# cppaillier
Paillier homomorphic encryption implemented in C++. Including some ZKPs.



## How to build

1. Install gmp library if you don't have it already https://gmplib.org
2. Install mppp https://github.com/bluescarni/mppp
3. ```bash
    git clone https://github.com/kran6a/cppaillier
    ```
4. ```bash
    cd cppaillier
    ```
5. ```bash
    cmake .
    ```
6. ```bash
    make
    ```
7. ```bash
    ./paillier_test
    ```




Note: this project has only been tested in armv8 architecture and uses rather aggressive optimization flags. If the test fails in your machine try removing some flags or lowering the optimization level from -Ofast to -O3 or even lower.
