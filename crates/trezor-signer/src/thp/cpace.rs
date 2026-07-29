//! CPace255 — the balanced PAKE used by THP CodeEntry pairing.
//!
//! An instance of CPace (draft-irtf-cfrg-cpace) for group G_X25519: the
//! generator is derived from the low-entropy pairing code and the Noise
//! handshake hash via `elligator2(SHA-512(generator_string)[..32])`
//! (`map_to_curve_elligator2_curve25519`, RFC 9380 §G.2.1), then both sides run
//! plain X25519 on it. Mirrors the reference host implementation in trezorlib
//! (`trezorlib/thp/cpace.py` + `curve25519.py`); the unit tests pin vectors
//! generated from that reference.
//!
//! Field arithmetic uses `num-bigint` and is not constant-time — same posture
//! as the pure-Python reference. The only secret here is the 6-digit code the
//! device is already displaying to the user.

use num_bigint::BigUint;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::x25519;

/// CPace domain separation identifier.
const DSI: &[u8] = b"CPace255";
/// SHA-512 block size, used for zero-padding the generator string.
const HASH_BLOCK_SIZE: usize = 128;

/// Result of the host side of a CPace exchange.
pub(crate) struct CpaceHost {
    /// Host public share (`cpace_host_public_key`).
    pub host_pubkey: [u8; 32],
    /// `SHA-256(shared_secret)` — the `tag` the device verifies.
    pub tag: [u8; 32],
}

/// Run the host side of CPace255: derive the generator from the pairing
/// `code` and the channel's `handshake_hash`, then do X25519 against the
/// device's public share.
pub(crate) fn cpace_host(
    code: &[u8],
    handshake_hash: &[u8; 32],
    trezor_pubkey: &[u8; 32],
) -> CpaceHost {
    let mut host_privkey = [0u8; 32];
    getrandom::fill(&mut host_privkey).expect("getrandom failed");
    cpace_host_with_privkey(code, handshake_hash, trezor_pubkey, &host_privkey)
}

fn cpace_host_with_privkey(
    code: &[u8],
    handshake_hash: &[u8; 32],
    trezor_pubkey: &[u8; 32],
    host_privkey: &[u8; 32],
) -> CpaceHost {
    let generator = generator(code, handshake_hash);
    let host_pubkey = x25519(*host_privkey, generator);
    let shared_secret = x25519(*host_privkey, *trezor_pubkey);
    CpaceHost {
        host_pubkey,
        tag: Sha256::digest(shared_secret).into(),
    }
}

/// `g = elligator2(SHA-512(generator_string(DSI, prs, zpad, ci, sid))[..32])`
fn generator(prs: &[u8], ci: &[u8]) -> [u8; 32] {
    let gen_str = generator_string(prs, ci);
    let digest = Sha512::digest(&gen_str);
    elligator2(digest[..32].try_into().unwrap())
}

/// Length-value concatenation per the CPace draft. Lengths are LEB128; every
/// input here is ≤ 127 bytes so a single byte always suffices.
fn generator_string(prs: &[u8], ci: &[u8]) -> Vec<u8> {
    let len_zpad = HASH_BLOCK_SIZE.saturating_sub(DSI.len() + 1 + prs.len() + 1 + 1);
    let mut out = Vec::new();
    for part in [DSI, prs, &vec![0u8; len_zpad], ci, &[][..]] {
        assert!(part.len() <= 0x7F, "lv_cat part too long");
        out.push(part.len() as u8);
        out.extend_from_slice(part);
    }
    out
}

/// This function helps the device and the host to derive a secret G point
/// to use in the Space protocol (an improvement on ECDH).
///
/// `map_to_curve_elligator2_curve25519`, returning only the u-coordinate.
/// Direct transliteration of the trezorlib reference.
///
/// To audit, read side by side with RFC 9380 §G.2.1
/// (<https://datatracker.ietf.org/doc/html/rfc9380#appendix-G.2.1>), the
/// curve25519 procedure this mirrors statement for statement. Its
/// `q = 5 (mod 8)` precondition is why `c3` and `c4` below take this form.
///
/// The device runs its own C implementation of the same map
/// (`crypto/elligator2.c` in the firmware), so any divergence here is silent:
/// the generators differ, the CPace tags mismatch, and pairing fails as if the
/// user mistyped the code. The unit tests below pin the output against vectors
/// generated from trezorlib for exactly that reason.
fn elligator2(point: &[u8; 32]) -> [u8; 32] {
    let p = BigUint::from(2u8).pow(255) - 19u8;
    let j = BigUint::from(486662u32);
    // c3 = sqrt(-1). The §G.2.1 precondition q ≡ 5 (mod 8) makes 2 a quadratic
    // non-residue, so 2^((q-1)/4) is a square root of -1.
    let c3 = BigUint::from(2u8).modpow(&((&p - 1u8) >> 2), &p);
    // c4 = (q - 5) / 8
    let c4 = (&p - 5u8) >> 3;

    let mul = |a: &BigUint, b: &BigUint| (a * b) % &p;
    let add = |a: &BigUint, b: &BigUint| (a + b) % &p;
    let sub = |a: &BigUint, b: &BigUint| (a + &p - (b % &p)) % &p;

    // decode_coordinate: little-endian, high bit masked, reduced mod p
    let mut bytes = *point;
    bytes[31] &= 0x7F;
    let u = BigUint::from_bytes_le(&bytes) % &p;

    let tv1 = mul(&u, &u);
    let tv1 = add(&tv1, &tv1);
    let xd = add(&tv1, &BigUint::from(1u8));
    let x1n = sub(&BigUint::from(0u8), &j); // -J mod p
    let tv2 = mul(&xd, &xd);
    let gxd = mul(&tv2, &xd);
    let gx1 = mul(&j, &tv1);
    let gx1 = mul(&gx1, &x1n);
    let gx1 = add(&gx1, &tv2);
    let gx1 = mul(&gx1, &x1n);
    let tv3 = mul(&gxd, &gxd);
    let tv2 = mul(&tv3, &tv3);
    let tv3 = mul(&tv3, &gxd);
    let tv3 = mul(&tv3, &gx1);
    let tv2 = mul(&tv2, &tv3);
    let y11 = tv2.modpow(&c4, &p);
    let y11 = mul(&y11, &tv3);
    let y12 = mul(&y11, &c3);
    let tv2 = mul(&y11, &y11);
    let tv2 = mul(&tv2, &gxd);
    let e1 = tv2 == gx1;
    let y1 = if e1 { y11 } else { y12 };
    let x2n = mul(&x1n, &tv1);
    let tv2 = mul(&y1, &y1);
    let tv2 = mul(&tv2, &gxd);
    let e3 = tv2 == gx1;
    let xn = if e3 { x1n } else { x2n };
    // x = xn / xd
    let x = mul(&xn, &xd.modpow(&(&p - 2u8), &p));

    let mut out = [0u8; 32];
    let le = x.to_bytes_le();
    out[..le.len()].copy_from_slice(&le);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // All expected values generated from the trezorlib reference
    // (curve25519.py / cpace.py) — see the module docs.

    #[test]
    fn elligator2_matches_reference() {
        let input: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hex::encode(elligator2(&input)),
            "5f3520001c6c9936a31206afe7c7ac224e8861619bf98872444915899d95f46e"
        );
    }

    #[test]
    fn x25519_matches_reference() {
        let k = [7u8; 32];
        let mut u = [0u8; 32];
        u[0] = 9;
        assert_eq!(
            hex::encode(x25519(k, u)),
            "13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d"
        );
    }

    #[test]
    fn cpace_host_matches_reference() {
        let code = b"123456";
        let handshake_hash = [0xAB; 32];
        // gen_str = lv_cat("CPace255", "123456", zpad[111], handshake_hash, "")
        let gen_str = generator_string(code, &handshake_hash);
        let mut expected = String::from("084350616365323535063132333435366f");
        expected.push_str(&"00".repeat(111));
        expected.push_str("20");
        expected.push_str(&"ab".repeat(32));
        expected.push_str("00");
        assert_eq!(hex::encode(&gen_str), expected);
        assert_eq!(
            hex::encode(generator(code, &handshake_hash)),
            "d024b17efef622399c7fbdfd962b1182a0e20c3e11e33b226beca1ff19dd9c01"
        );

        let trezor_pubkey: [u8; 32] =
            hex::decode("ba193836cff1f4e866c139715d306408d26a76f76d638a39afc1001084d25411")
                .unwrap()
                .try_into()
                .unwrap();
        let result = cpace_host_with_privkey(code, &handshake_hash, &trezor_pubkey, &[0x42u8; 32]);
        assert_eq!(
            hex::encode(result.host_pubkey),
            "97b4dbe22390b0a1992171811728aa017312cb66549056d9899bd2994dc04b59"
        );
        assert_eq!(
            hex::encode(result.tag),
            "28b7b4f1a1cf0bd8f8023d4d436ba0a3707cb1572f1d65261be9892aa91864c4"
        );
    }
}
