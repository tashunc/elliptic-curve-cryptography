# Elliptic Curve Cryptography 

ECC function and related functionalities to calculate the Ethereum public address are implemented here from scratch. 

Functionalities include,
1. elliptic curve multiplication
2. elliptic curve addition
3. elliptic curve double
4. elliptic curve modular inverse



Secp256k1 and ECC maths related implementations are in a separated Library
`secp256k1_lib/src/lib.rs`


Test
```
    cargo test
```
Watch Run 

```
cargo.exe watch -q -c -x 'run -q'
```