use criterion::{criterion_group, criterion_main, Criterion};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::hint::black_box;

fn keccak(c: &mut Criterion) {
    let seed = [3u8; 34];
    c.bench_function("shake128 1008B (qtv-crypto)", |b| {
        b.iter(|| {
            let mut out = [0u8; 1008];
            qtv_crypto::sha3::shake128(black_box(&seed), &mut out);
            out
        })
    });
    c.bench_function("shake128 1008B (sha3 crate)", |b| {
        b.iter(|| {
            let mut h = sha3::Shake128::default();
            h.update(black_box(&seed));
            let mut out = [0u8; 1008];
            h.finalize_xof().read(&mut out);
            out
        })
    });
}

criterion_group!(benches, keccak);
criterion_main!(benches);
