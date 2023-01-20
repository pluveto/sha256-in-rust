fn compress(input_bytes: &Vec<u8>) -> [u32; 8] {
    static H: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    static K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut hash = H;
    let nblocks = input_bytes.len() / 64;
    for i in 0..nblocks {
        let mut w = [0; 64];
        for j in 0..16 {
            let offset = i * 64 + j * 4;
            w[j] = ((input_bytes[offset + 0] as u32) << 24)
                | ((input_bytes[offset + 1] as u32) << 16)
                | ((input_bytes[offset + 2] as u32) << 8)
                | ((input_bytes[offset + 3] as u32) << 0);
        }
        for j in 16..64 {
            let s0 = w[j - 15].rotate_right(7) ^ w[j - 15].rotate_right(18) ^ (w[j - 15] >> 3);
            let s1 = w[j - 2].rotate_right(17) ^ w[j - 2].rotate_right(19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16]
                .wrapping_add(s0)
                .wrapping_add(w[j - 7])
                .wrapping_add(s1);
        }
        let mut working: [u32; 8] = hash; // working variables
        for j in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choose = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[j])
                .wrapping_add(w[j]);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let major =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = s0.wrapping_add(major);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }

        for j in 0..8 {
            hash[j] = hash[j].wrapping_add(working[j]);
        }
    }
    return hash;
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    // padding
    let mut input_bytes = input.to_vec();
    let input_len = input_bytes.len();
    let padding_len = if input_len % 64 < 56 {
        56 - input_len % 64
    } else {
        120 - input_len % 64
    };

    input_bytes.push(0x80); // 1000 0000
    for _ in 0..padding_len - 1 {
        input_bytes.push(0x00);
    }
    assert!(input_bytes.len() % 64 == 56);
    let input_bit_len = input_len * 8;
    for i in 0..8 {
        let byte = ((input_bit_len >> (56 - i * 8)) & 0xff) as u8;

        input_bytes.push(byte);
    }

    assert!(input_bytes.len() % 64 == 0);

    let hash = compress(&input_bytes);

    let mut ret = [0 as u8; 32];
    for i in 0..8 {
        ret[i * 4 + 0] = ((hash[i] >> 24) & 0xff) as u8;
        ret[i * 4 + 1] = ((hash[i] >> 16) & 0xff) as u8;
        ret[i * 4 + 2] = ((hash[i] >> 8) & 0xff) as u8;
        ret[i * 4 + 3] = ((hash[i] >> 0) & 0xff) as u8;
    }

    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    fn u8array_to_string(arr: &[u8]) -> String {
        let mut ret = String::new();
        for i in arr {
            ret.push_str(&format!("{:02x}", i));
        }
        ret
    }
    #[test]
    fn short_string_test() {
        let tests = [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "less-bug.com",
                "201ab7036478ee8aba2eb3c7c0c65b8b17495852f4ebe15b79e534396f290c5b",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (input, expected) in tests.iter() {
            let input_bytes = input.as_bytes();
            let output = sha256(input_bytes);

            let output_string = u8array_to_string(&output);
            assert_eq!(output_string, *expected);
        }
    }

    #[test]
    fn long_string_test() {
        let input = {
            let mut ret = String::new();
            for _ in 0..(512 * 16 + 500) {
                ret.push_str("a");
            }
            ret
        };
        let expected =
            "31ef976b92b5879f6068892a737803b40dac69e6a9c5563e05dd6197b2b39a27".to_string();
        let input_bytes = input.as_bytes();
        let output = sha256(input_bytes);
        let output_string = u8array_to_string(&output);
        assert_eq!(output_string, expected);
    }
}
