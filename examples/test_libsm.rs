use libsm::sm3::hash::Sm3Hash;

fn main() {
    let mut sm3 = Sm3Hash::new(b"abc");
    let hash = sm3.get_hash();
    println!("libsm result: {:02x?}", hash);
    println!("Expected: 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0");
}
