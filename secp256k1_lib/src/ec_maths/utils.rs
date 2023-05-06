use num_bigint::BigInt;

pub fn convert_to_binary_from_hex(hex: String) -> String {
    let to_binary = hex[2..]
        .chars()
        .map(|c| to_binary(c))
        .collect();

    to_binary
}

fn to_binary(c: char) -> String {
    let b = match c {
        '0' => "0000",
        '1' => "0001",
        '2' => "0010",
        '3' => "0011",
        '4' => "0100",
        '5' => "0101",
        '6' => "0110",
        '7' => "0111",
        '8' => "1000",
        '9' => "1001",
        'A' => "1010",
        'B' => "1011",
        'C' => "1100",
        'D' => "1101",
        'E' => "1110",
        'F' => "1111",
        _ => "",
    };

    b.to_string()
}

pub fn append_prefix(public_key: (BigInt, BigInt)) -> String {
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
    return concat_public_key;
}