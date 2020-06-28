
#[macro_use]
extern crate hex_literal;

use bitmaps::Bitmap;
use typenum::U1024;
use parity_crypto::publickey::{Generator, KeyPair, Error};
use tiny_keccak::{Keccak, Hasher};
use primitive_types::{H160, H256};
use bit_field::BitField;
use std::cmp;
use std::cmp::{ Ordering, Ord };

pub fn keccak256(data : &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut output = [0u8; 32];
    keccak.finalize(&mut output);
    output
}

pub fn count_bit(byte : u8) -> u8 {
    let mut count = 0u8;
    let mut foo = 1u8;
    for i in 0..8 {
        if(byte & foo != 0) {
            count += 1;
        }
        foo <<= 1;
    }
    count
}

//pk_hash + pb_hash + round + bm[0..n] as initial input data of next round hash-function
//do not use unixtime. because unixtime can be used to parrallel computation.
//length of bitmap is variable, not constant.

pub fn set_bitmap(round : u32, last_byte : u8, bm : &[u8]) {
    if count_bit(last_byte) % 2 == 0 {
        //set 0
    } else {
        //set 1
    }
}

pub fn keccak256_ntimes(data : &[u8], ntimes : u64, target : &H256) -> [u8; 32] {
    let mut input = data ;
    let mut output = [0u8; 32];
    for i in 0..ntimes {
        output = keccak256(input);
        if in_target(&H256::from(output), target) {
            println!("count = {}", i);
            break;
        }
        input = &output;
    }
    output
}

pub fn bytes_compare(a: &[u8], b: &[u8]) -> cmp::Ordering {
    for (ai, bi) in a.iter().zip(b.iter()) {
        match ai.cmp(&bi) {
            Ordering::Equal => continue,
            ord => return ord
        }
    }
    // if every single element was equal, compare length
    a.len().cmp(&b.len())
}

pub fn in_target(hash : &H256, target : &H256) -> bool {
    match bytes_compare(hash.as_bytes(), target.as_bytes()) {
        Ordering::Greater => false,
        _ =>  true
    }
}

fn main() {
    let key_pair = KeyPair::from_secret("01234567890abcdef00000000f5a92a7a8328a5c85bb2f9542e76f9b0f94fc18".parse().unwrap()).unwrap();
    let sk = key_pair.secret();
    let pk = key_pair.public();
    println!("{:x}", pk);
    //let pk_hex = format!("0x{:x}", pk);
    let pk_bytes = pk.as_bytes();
    println!("{:x?}", pk_bytes);
    let pk_hash = keccak256(pk_bytes);
    println!("{:x?}", pk_hash);
    let foo  = H256::from(pk_hash);
    println!("{:x}", foo);
    let pb_hash = keccak256(b"previous_block_hash");
    let foo = H256::from(pb_hash);
    println!("{:x}", foo);
    //let pk_pb_hash = vec!(&pk_hash, &pb_hash);
    //println!("{:x?}", pk_pb_hash);
    let mut pk_pb_hash = pk_hash.to_vec();
    pk_pb_hash.extend(&pb_hash);
    println!("{:x?}", pk_pb_hash);
    let hash = keccak256(&pk_pb_hash);
    println!("##{:x?}", hash);
    let target = H256::from(hex!("000000ffff1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"));
    let hash = keccak256_ntimes(&pk_pb_hash, 1000_0000, &target);
    println!("=={:x?}", hash);
    let result = in_target(&H256::from(hash), &target);
    println!("=={:x?}", result);
}

#[test]
fn test() {
    println!("{}", count_bit(0xff));
    println!("{}", count_bit(0xf0));
    println!("{}", count_bit(0x0f));
    println!("{}", count_bit(0xef));
    println!("{}", count_bit(0xfe));
    println!("{}", count_bit(0x00));
    println!("{}", count_bit(0x80));
    println!("{}", count_bit(0x01));
    //assert_eq!(8, count_bit(0xf0));
    //assert_eq!(8, count_bit(0x0f));
    //assert_eq!(8, count_bit(0xe0));
    //assert_eq!(8, count_bit(0x1e));
    //assert_eq!(8, count_bit(0x8f));

    let mut x: u8 = 0;

    x.set_bit(7, true);
    assert_eq!(x, 0b1000_0000);

    x.set_bits(0..4, 0b1011);
    assert_eq!(x, 0b1000_1011);

    let mut bitmap = Bitmap::<U1024>::new();
    assert_eq!(bitmap.set(5, true), false);
    assert_eq!(bitmap.set(5, true), true);
    assert_eq!(bitmap.get(5), true);
    assert_eq!(bitmap.get(6), false);
    assert_eq!(bitmap.len(), 1);
    assert_eq!(bitmap.set(3, true), false);
    assert_eq!(bitmap.len(), 2);
    assert_eq!(bitmap.first_index(), Some(3));

    // https://cn.etherscan.com/getRawTx?tx=0x083cc4af906c0b8b67a630507f695aa0dab2bde84fada412fff608d0ee9ea1ae
    let tx = hex!("f8ad830dd98a8502540be40083026739947c2af3a86b4bf47e6ee63ad9bde7b3b0ba7f95da80b844
    a9059cbb000000000000000000000000b34938746d316e995aa81f9b3f94419a0a41e14300000000000000000000000000000000000000000000026faff2dfe5c524000025a0
    167bf6ce1f7ecee1e5a414e3622baa14daf6caaf90f498b4fb94b1a91bc79491a0
    362191d3956065a0e14276dd4810b523e93a786091d27388a2b00b6955f93161");

    let hash =  keccak256(&tx);
    assert_eq!(hash, hex!("083cc4af906c0b8b67a630507f695aa0dab2bde84fada412fff608d0ee9ea1ae"));

    let foo = H256::from(hash);
    println!("0x{:x}", foo);

    let rlp_obj = rlp::Rlp::new(&tx);
    println!("data: {}", rlp_obj);
}


