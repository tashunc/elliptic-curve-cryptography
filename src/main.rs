#![allow(unused)] // ignore

use std::str::FromStr;
use ethereum_types::H160;
use num_bigint::BigInt;
use num_traits::Num;
use sha3::{Digest, Keccak256};
// silence unused till final commit
use secp256k1_lib::ec_maths::ec_multiply;
use rand::Rng;
use substring::Substring;

struct Args {
    gx: String,
    gy: String,
    private_key: String,
}

fn main() {
    // let private_key: BigInt = BigInt::from_str_radix("a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e", 16).unwrap();
    let mut is_found = false;
    while !is_found {
        let gx: BigInt = BigInt::from_str("55066263022277343669578718895168534326250603453777594175500187360389116729240").unwrap();
        let gy: BigInt = BigInt::from_str("32670510020758816978083085130507043184471273380659243275938904335757337482424").unwrap();
        let mut rng = rand::thread_rng();
        // generate random 32 bytes
        let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen_range(0..=255)).collect();
        let private_key_string = hex::encode(random_bytes);
        // convert to Big Int
        let private_key: BigInt = BigInt::from_str_radix(&private_key_string, 16).unwrap();


        let public_key: (BigInt, BigInt) = ec_multiply(gx, gy, private_key);
        let concat_public_key = secp256k1_lib::ec_maths::utils::append_prefix(public_key);


        let public_key = hex::decode(concat_public_key).unwrap();


        let address = H160::from_slice(&Keccak256::digest(&public_key[1..]).as_slice()[12..]);
        is_found = format!("{:X}", address).to_string().to_lowercase().substring(0, 5) == "00000";
        if (is_found) {

            println!("{}",format!("{:X}", address).to_string().to_lowercase());
            println!("{}",is_found);
            println!("{}",private_key_string);
        }
    }

}


#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use ethereum_types::H160;
    use num_bigint::BigInt;
    use num_traits::Num;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use sha3::{Digest, Keccak256};
    use secp256k1_lib::ec_maths::ec_multiply;

    #[test]
    fn testing_ethereum_public_address_given_private_key() {
        let gx: BigInt = BigInt::from_str("55066263022277343669578718895168534326250603453777594175500187360389116729240").unwrap();
        let gy: BigInt = BigInt::from_str("32670510020758816978083085130507043184471273380659243275938904335757337482424").unwrap();
        let private_key: BigInt = BigInt::from_str("72759466100064397073952777052424474334519735946222029294952053344302920927294").unwrap();

        let public_key: (BigInt, BigInt) = ec_multiply(gx, gy, private_key);
        // println!("x = {}, y = {}", publicKey.0, publicKey.1);
        // println!("020{:X}", publicKey.0);
        assert_eq!(public_key.0, BigInt::from_str("3423904187495496827825042940737875085827330420143621346629173781207857376010").unwrap());
        assert_eq!(public_key.1, BigInt::from_str("75711134420273723792089656449854389054866833762486990555172221523628676983696").unwrap());

        let mut concat_public_key = format!("{:X}", public_key.0) + &*format!("{:X}", public_key.1);
        if public_key.1.modpow(&BigInt::from(1), &BigInt::from(2)) == BigInt::from(1) {
            if concat_public_key.len() % 2 == 0 {
                concat_public_key = format!("03{}", concat_public_key);
            } else {
                concat_public_key = format!("030{}", concat_public_key);
            }
        } else {
            if concat_public_key.len() % 2 == 0 {
                concat_public_key = format!("02{}", concat_public_key);
            } else {
                concat_public_key = format!("020{}", concat_public_key);
            }
        }
        println!("{}", concat_public_key.to_lowercase());
        let public_key = hex::decode(concat_public_key).unwrap();
        //
        assert_eq!(public_key, [2, 7, 145, 220, 112, 183, 90, 169, 149, 33, 50, 68, 173, 63, 72, 134, 215, 77, 97, 204, 211, 239, 101, 130, 67, 252, 173, 20, 201, 204, 238, 43, 10, 167, 98, 251, 198, 172, 9, 33, 184, 241, 112, 37, 187, 132, 88, 185,
            39, 148, 174, 135, 161, 51, 137, 77, 112, 215, 153, 95, 192, 182, 181, 171, 144]);

        let address = H160::from_slice(&Keccak256::digest(&public_key[1..]).as_slice()[12..]);
        assert_eq!("9f62d99c36af327a84e3fd29091e5bd4edf29609", format!("{:X}", address).to_string().to_lowercase());
    }

    #[test]
    fn testing_ethereum_public_address_given_private_key_hex() {
        let gx: BigInt = BigInt::from_str("55066263022277343669578718895168534326250603453777594175500187360389116729240").unwrap();
        let gy: BigInt = BigInt::from_str("32670510020758816978083085130507043184471273380659243275938904335757337482424").unwrap();
        let private_key: BigInt = BigInt::from_str_radix("a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e", 16).unwrap();

        let public_key: (BigInt, BigInt) = ec_multiply(gx, gy, private_key);
        // println!("x = {}, y = {}", publicKey.0, publicKey.1);
        // println!("020{:X}", publicKey.0);
        assert_eq!(public_key.0, BigInt::from_str("3423904187495496827825042940737875085827330420143621346629173781207857376010").unwrap());
        assert_eq!(public_key.1, BigInt::from_str("75711134420273723792089656449854389054866833762486990555172221523628676983696").unwrap());


        let d = format!("020{:X}", public_key.0) + &*format!("{:X}", public_key.1);
        let public_key = hex::decode(d).unwrap();
        //
        assert_eq!(public_key, [2, 7, 145, 220, 112, 183, 90, 169, 149, 33, 50, 68, 173, 63, 72, 134, 215, 77, 97, 204, 211, 239, 101, 130, 67, 252, 173, 20, 201, 204, 238, 43, 10, 167, 98, 251, 198, 172, 9, 33, 184, 241, 112, 37, 187, 132, 88, 185,
            39, 148, 174, 135, 161, 51, 137, 77, 112, 215, 153, 95, 192, 182, 181, 171, 144]);

        let address = H160::from_slice(&Keccak256::digest(&public_key[1..]).as_slice()[12..]);
        assert_eq!("9f62d99c36af327a84e3fd29091e5bd4edf29609", format!("{:X}", address).to_string().to_lowercase());
    }

    #[test]
    fn testing_ethereum_public_address_using_libs() {
        let private_key_str = "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e";
        let private_key = hex::decode(private_key_str).expect("Decoding failed");
        let secp = Secp256k1::new();

        let secret_key = SecretKey::from_slice(&private_key).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        println!("{}", public_key);


        let serialized_public_key = public_key.serialize_uncompressed();
        println!("UnCompressed{:?}", serialized_public_key);
        //
        let address = H160::from_slice(&Keccak256::digest(&serialized_public_key[1..]).as_slice()[12..]);
        println!("{:?}", address);
    }
}

