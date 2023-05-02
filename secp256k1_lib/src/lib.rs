// ================= Functional Checks ===============================


pub mod ec_maths;

use num::{BigInt};

pub fn is_coordinates_on_curve(x: BigInt, y: BigInt) -> bool {
    return get_secp256k1(x, y) == BigInt::from(0);
}

fn get_secp256k1(x: BigInt, y: BigInt) -> BigInt {
    return x.pow(3) + 7 - y.pow(2);
}
