/// Create unspenable pubkey like taproot bip 0341 described:
/// "...pick as internal key a point with unknown discrete logarithm. 
/// One example of such a point is H = lift_x(0x0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0) which is constructed 
/// by taking the hash of the standard uncompressed encoding of the secp256k1 base point G as X coordinate. 
/// In order to avoid leaking the information that key path spending is not possible it is recommended to 
/// pick a fresh integer r in the range 0...n-1 uniformly at random and use H + rG as internal key. 
/// It is possible to prove that this internal key does not have a known discrete logarithm with respect to G 
/// by revealing r to a verifier who can then reconstruct how the internal key was created."
/// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
use secp256k1::*;
use rand::{Rng};

const H_HEX: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const G_HEX: &str = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

fn tweak_for_unspendable() {

    let H = PublicKey::from_slice(hex::decode(H_HEX).expect("valid hex").as_ref()).expect("valid pubkey hex");
    let G = PublicKey::from_slice(hex::decode(G_HEX).expect("valid hex").as_ref()).expect("valid pubkey hex");

    // Sample r
    // let r = hex::decode("0197e7e118cd26d2146f9fed5dee89133187a3c3e9d2e68ccafe93a1d5c85e2a").expect("valid hex");
    // let r = hex::decode("0101010101010101010101010101010101010101010101010101010101010101").expect("valid hex");

    // Random r of 32 byte (could be a txid)
    // r must be 0..FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141 - 1
    let mut rng = rand::thread_rng();
    let r = rng.gen::<[u8;32]>();

    let secp = Secp256k1::new();
    let mut pk_rG = G;

    pk_rG.mul_assign(&secp, r.as_slice()).expect("cannot mul r x H");      // r*G
    let unspendable_pk = H.combine(&pk_rG).expect("invalid combine");  // H + rG

    println!("unspendable_pk={:?}", unspendable_pk.to_string());
}

fn main() {
    tweak_for_unspendable();
}
