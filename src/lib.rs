// Dependencies
use std::{str, convert::TryInto};
use base64::{engine::general_purpose, Engine};

/// Gets the right shift value.
fn shift_right(i_value: i32, i_count: i32) -> i32 {
    let i_value = i_value as i64;
    if i_value & 0x80000000 != 0 {
        ((i_value >> i_count) ^ 0xFFFF0000).try_into().unwrap()
    } else {
        (i_value >> i_count).try_into().unwrap()
    }
}

/// Reads a 32-bit signed from a `&[u8]`. Returns the number as a 64-bit signed
fn get_long(bytes: &[u8], index: i32) -> i64 {
    let index: usize = index.try_into().unwrap();
    let x = ((bytes[index] as i32) << 24) |
    ((bytes[index + 1] as i32) << 16) |
    ((bytes[index + 2] as i32) << 8) |
    (bytes[index + 3] as i32);
    x as i64
}

/// A map structure used for [`get_hash`].
#[derive(Default)]
struct MapHash {
    p_data: i32,
    cache: i64,
    counter: i32,
    index: i32,

    md5_1: i64,
    md5_2: i64,

    out_hash_1: i32,
    out_hash_2: i32,

    // I assume these are registers
    r0: i32,
    r1: [i32; 2],
    r2: [i32; 2],
    r3: i32,
    r4: [i32; 2],
    r5: [i32; 2],
    r6: [i32; 2]
}

/// Hashes a `base_info`. The final step.
/// 
/// We treat everything as a 64-bit signed but then convert back into 32-signed.
/// Currently not working!
pub fn get_hash(base_info: &str) -> String {
    // Converts the base_info to a byte array and appends 0, 0 to it
    let mut bytes_base_info: Vec<u8> = base_info.as_bytes().to_vec();
    bytes_base_info.extend_from_slice(&[0x00, 0x00]);

    // Calculate the MD5 for it
    let bytes_md5 = md5::compute(&bytes_base_info).to_vec();

    // Figure out the length we're going to use
    let length_base = (base_info.len() * 2) + 2;
    let length = if length_base & 4 <= 1 {
        1
    } else {
        0
    } + (length_base >> 2) - 1;
    let length: i64 = length.try_into().unwrap();

    // Invalid?
    if length <= 1 {
       return String::from("");
    }

    // Initialise our map
    let mut map = MapHash::default();

    // Set some things for the map...
    map.md5_1 = (get_long(&bytes_md5, 0) | 1) + 0x69FB0000;
    map.md5_2 = (get_long(&bytes_md5, 4) | 1) + 0x13DB0000;
    map.index = shift_right((length - 2).try_into().unwrap(), 1) as i32;
    map.counter = map.index + 1;

    // First hasher
    while map.counter >= 0 {
        // Set a lot of properties...
        map.r0 = (get_long(&bytes_base_info, map.p_data) + map.out_hash_1 as i64) as i32;
        map.r1[0] = get_long(&bytes_base_info, map.p_data + 4) as i32;
        map.p_data += 8;

        map.r2[0] = ((map.r0 as i64 * map.md5_1) - (0x10FA9605 * shift_right(map.r0, 16)) as i64) as i32;
        map.r2[1] = ((0x79F8A395 * map.r2[0] as i64) + (0x689B6B9F * shift_right(map.r2[0], 16)) as i64) as i32;

        map.r3 = ((0xEA970001 * map.r2[1] as i64) - (0x3C101569 * shift_right(map.r2[1], 16) as i64)) as i32;

        map.r4[0] = map.r3 + map.r1[0];
        map.r5[0] = (map.cache + map.r3 as i64) as i32;

        map.r6[0] = ((map.r4[0] as i64 * map.md5_2) - (0x3CE8EC25 * shift_right(map.r4[0], 16)) as i64) as i32;
        map.r6[1] = ((0x59C3AF2D * map.r6[0] as i64) - (0x2232E0F1 * shift_right(map.r6[0], 16) as i64)) as i32;

        map.out_hash_1 = (0x1EC90001 * map.r6[1]) + (0x35BD1EC9 * shift_right(map.r6[1], 16));
        map.out_hash_2 = (map.r5[0] as i64 + map.out_hash_1 as i64) as i32;
        map.cache = map.out_hash_2 as i64;
        map.counter = map.counter - 1;
    }

    // Finalising results
    let mut out_hash: [u8; 16] = [0; 16];
    out_hash[0..4].copy_from_slice(&map.out_hash_1.to_be_bytes());
    out_hash[4..8].copy_from_slice(&map.out_hash_2.to_be_bytes());

    // Reset for next hasher
    let mut map = MapHash::default();

    // Set some things for the map...
    map.md5_1 = get_long(&bytes_md5, 0) | 1;
    map.md5_2 = get_long(&bytes_md5, 4) | 1;
    map.index = shift_right((length - 2).try_into().unwrap(), 1);
    map.counter = map.index + 1;

    // Second hasher
    while map.counter >= 0 {
        // Set a lot of properties...
        map.r0 = (get_long(&bytes_base_info, map.p_data) + map.out_hash_1 as i64) as i32;
        map.p_data += 8;
        map.r1[0] = (map.r0 as i64 * map.md5_1) as i32;
        map.r1[1] = ((0xB1110000 * map.r1[0] as i64) - (0x30674EEF * shift_right(map.r1[0], 16) as i64)) as i32;

        map.r2[0] = (0x5B9F0000 * map.r1[1]) - (0x78F7A461 * shift_right(map.r1[1], 16));
        map.r2[1] = (0x12CEB96D * shift_right(map.r2[0], 16)) - (0x46930000 * map.r2[0]);

        map.r3 = (0x1D830000 * map.r2[1]) + (0x257E1D83 * shift_right(map.r2[1], 16));

        map.r4[0] = (map.md5_2 * (map.r3 as i64 + get_long(&bytes_base_info, map.p_data - 4))) as i32;
        map.r4[1] = (0x16F50000 * map.r4[0]) - (0x5D8BE90B * shift_right(map.r4[0], 16));

        map.r5[0] = ((0x96FF0000 * map.r4[1] as i64) - (0x2C7C6901 * shift_right(map.r4[1], 16) as i64)) as i32;
        map.r5[1] = (0x2B890000 * map.r5[0]) + (0x7C932B89 * shift_right(map.r5[0], 16));

        map.out_hash_1 = ((0x9F690000 * map.r5[1] as i64) - (0x405B6097 * shift_right(map.r5[1], 16) as i64)) as i32;
        map.out_hash_2 = (map.out_hash_1 as i64 + map.cache + map.r3 as i64) as i32;
        map.cache = map.out_hash_2 as i64;
        map.counter = map.counter - 1;
    }

    // Finalising results
    out_hash[0..8].copy_from_slice(&map.out_hash_1.to_be_bytes());
    out_hash[8..12].copy_from_slice(&map.out_hash_2.to_be_bytes());
    
    // Done
    let mut out_hash_base: [u8; 8] = [0; 8];
    let hash_value_1 = (get_long(&out_hash, 8) ^ get_long(&out_hash, 0)).to_be_bytes();
    let hash_value_2 = (get_long(&out_hash, 12) ^ get_long(&out_hash, 4)).to_be_bytes();
    out_hash_base[0..4].copy_from_slice(&hash_value_1);
    out_hash_base[4..8].copy_from_slice(&hash_value_2);

    // Export as b64
    general_purpose::STANDARD.encode(out_hash_base)   
}