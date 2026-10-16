use criterion::{criterion_group, criterion_main, Criterion};
use k256::schnorr::signature::{RandomizedSigner, Verifier};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use std::hint::black_box;

const MSG: [u8; 32] = [0x5a; 32];

fn fresh(c: &mut Criterion) {
    let sk = SigningKey::random(&mut rand::rngs::OsRng);
    let pk = sk.verifying_key().to_bytes();
    let sig: Signature = sk.sign_with_rng(&mut rand::rngs::OsRng, &MSG);
    let sig = sig.to_bytes();
    c.bench_function("BIP340/decode+verify", |b| {
        b.iter(|| {
            let vk = VerifyingKey::from_bytes(black_box(&pk)).unwrap();
            let s = Signature::try_from(&sig[..]).unwrap();
            vk.verify(black_box(&MSG), &s).is_ok()
        })
    });
}

criterion_group!(benches, fresh);
criterion_main!(benches);
