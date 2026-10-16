use criterion::{criterion_group, criterion_main, Criterion};
use k256::schnorr::signature::{RandomizedSigner, Verifier};
use k256::schnorr::{Signature, SigningKey};
use std::hint::black_box;

const MSG: [u8; 32] = [0x5a; 32];

fn costs(c: &mut Criterion) {
    let sk = SigningKey::random(&mut rand::rngs::OsRng);
    let vk = *sk.verifying_key();
    let sig: Signature = sk.sign_with_rng(&mut rand::rngs::OsRng, &MSG);
    println!(
        "BIP340 pk={} sig={}",
        vk.to_bytes().len(),
        sig.to_bytes().len()
    );
    c.bench_function("BIP340/sign", |b| {
        b.iter(|| -> Signature { sk.sign_with_rng(&mut rand::rngs::OsRng, black_box(&MSG)) })
    });
    c.bench_function("BIP340/verify", |b| {
        b.iter(|| vk.verify(black_box(&MSG), &sig).unwrap())
    });
}

criterion_group!(benches, costs);
criterion_main!(benches);
