pub mod utils;

use std::ops::{Div, Mul, Sub};
use std::str::FromStr;
use num_bigint::BigInt;
use substring::Substring;

use crate::ec_maths::utils::convert_to_binary_from_hex;
// # Number of points in the field


fn ec_mod_inverse(x1: BigInt) -> BigInt {
    let p: BigInt = BigInt::from_str("115792089237316195423570985008687907853269984665640564039457584007908834671663").unwrap();


    let mut lm = BigInt::from(1);
    let mut hm = BigInt::from(0);
    let mut low = x1.modpow(&BigInt::from(1), &p.clone());
    let mut high = p.clone();
    while low.gt(&BigInt::from(1)) {
        let ratio = high.clone().div(low.clone());
        let nm = hm.clone().sub(lm.clone().mul(ratio.clone()));
        let new = high.clone().sub(low.clone().mul(ratio.clone()));
        high = low.clone();
        hm = lm.clone();
        lm = nm.clone();
        low = new.clone();
    }

    return lm.modpow(&BigInt::from(1), &p.clone());
}

fn ec_add(x1: &BigInt, y1: &BigInt, x2: &BigInt, y2: &BigInt, p: &BigInt) -> (BigInt, BigInt) {
    let m: BigInt = y2.sub(y1).mul(ec_mod_inverse(x2.sub(x1))).modpow(&BigInt::from(1), p);
    let x3: BigInt = m.clone().mul(m.clone()).sub(x2).sub(x1).modpow(&BigInt::from(1), p);
    let y3: BigInt = m.clone().mul(x1.sub(x3.clone())).sub(y1).modpow(&BigInt::from(1), p);
    return (x3, y3);
}

fn ec_double(x1: &BigInt, y1: &BigInt, p: &BigInt) -> (BigInt, BigInt) {
    let m_numerator: BigInt = x1.mul(x1).mul(3);
    let m_denominator: BigInt = y1.mul(2);
    let m = (m_numerator.clone().mul(ec_mod_inverse(m_denominator.clone()))).modpow(&BigInt::from(1), p);
    // println!("dgfdfg");
    // println!("{}",m);
    // println!("{}",ec_mod_inverse(m_denominator.clone()));
    let x3: BigInt = (m.clone().mul(m.clone())).sub(x1.clone()).sub(x1.clone()).modpow(&BigInt::from(1), p);
    let y3: BigInt = m.clone().mul(x1.sub(&x3)).sub(y1).modpow(&BigInt::from(1), p);
    return (x3, y3);
}



pub fn ec_multiply(xs: BigInt, ys: BigInt, scalar: BigInt) -> (BigInt, BigInt) {
    let n: BigInt = BigInt::from_str("115792089237316195423570985008687907852837564279074904382605163141518161494337").unwrap();
    let p: BigInt = BigInt::from_str("115792089237316195423570985008687907853269984665640564039457584007908834671663").unwrap();
    if scalar.eq(&BigInt::from(0)) || scalar.ge(&n) { panic!("Invalid Scalar/Private Key"); }
    let scalar_bin = convert_to_binary_from_hex(format!("0x{:X}", scalar));
    let mut qx = xs.clone();
    let mut qy = ys.clone();
    let mut i = 1;
    while i < scalar_bin.len() {
        let (a, b) = ec_double(&qx, &qy, &p);
        if scalar_bin.substring(i, i + 1) == "1" {
            let (c, d) = ec_add(&a, &b, &xs, &ys, &p);
            qx = c;
            qy = d;
        } else {
            qx = a;
            qy = b;
        }
        i = i + 1;
    }

    return (qx, qy);
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn testing_ecc_inverse() {
        let inverse_checker: BigInt = BigInt::from_str("65341020041517633956166170261014086368942546761318486551877808671514674964848").unwrap();

        let result = ec_mod_inverse(inverse_checker);
        assert_eq!(result, BigInt::from_str("83174505189910067536517124096019359197644205712500122884473429251812128958118").unwrap());
    }

    #[test]
    fn testing_sep256k1_public_key() {
        let gx: BigInt = BigInt::from_str("55066263022277343669578718895168534326250603453777594175500187360389116729240").unwrap();
        let gy: BigInt = BigInt::from_str("32670510020758816978083085130507043184471273380659243275938904335757337482424").unwrap();
        let priv_key: BigInt = BigInt::from_str("72759466100064397073952777052424474334519735946222029294952053344302920927294").unwrap();

        let result = ec_multiply(gx, gy, priv_key);
        assert_eq!(result.0, BigInt::from_str("3423904187495496827825042940737875085827330420143621346629173781207857376010").unwrap());
        assert_eq!(result.1, BigInt::from_str("75711134420273723792089656449854389054866833762486990555172221523628676983696").unwrap());
    }

}