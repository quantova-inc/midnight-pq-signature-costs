use criterion::{criterion_group, criterion_main, Criterion};
use ml_dsa::{
    Keypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, Signature, SigningKey, VerifyingKey,
};
use slh_dsa::{ParameterSet, Sha2_128f, Sha2_128s, Shake128f};
use std::hint::black_box;
use std::time::Duration;

const MSG: [u8; 32] = [0x5a; 32];

fn ml_dsa<P: MlDsaParams>(c: &mut Criterion, name: &str) {
    let sk = SigningKey::<P>::from_seed(&Seed::from([7u8; 32]));
    let pk = sk.verifying_key().encode();
    let sig = ml_dsa::Signer::sign(&sk, &MSG).encode();
    c.bench_function(&format!("{name}/decode+verify"), |b| {
        b.iter(|| {
            let vk = VerifyingKey::<P>::decode(black_box(&pk));
            let s = Signature::<P>::decode(&sig).unwrap();
            ml_dsa::Verifier::verify(&vk, black_box(&MSG), &s).is_ok()
        })
    });
}

fn slh_dsa<P: ParameterSet>(c: &mut Criterion, name: &str) {
    let sk = slh_dsa::SigningKey::<P>::new(&mut rand::rngs::OsRng);
    let pk = AsRef::<slh_dsa::VerifyingKey<P>>::as_ref(&sk).to_bytes();
    let sig: slh_dsa::Signature<P> = slh_dsa::signature::Signer::sign(&sk, &MSG);
    let sig = slh_dsa::signature::SignatureEncoding::to_bytes(&sig);
    let mut g = c.benchmark_group(name);
    g.sample_size(20).measurement_time(Duration::from_secs(10));
    g.bench_function("decode+verify", |b| {
        b.iter(|| {
            let vk = slh_dsa::VerifyingKey::<P>::try_from(black_box(&pk[..])).unwrap();
            let s = slh_dsa::Signature::<P>::try_from(&sig[..]).unwrap();
            slh_dsa::signature::Verifier::verify(&vk, black_box(&MSG), &s).is_ok()
        })
    });
    g.finish();
}

fn qtv(c: &mut Criterion) {
    let (pk, sk) = qtv_crypto::ml_dsa::keygen(&[7u8; 32]);
    let sig = qtv_crypto::ml_dsa::sign(&sk, &MSG, b"", &[0u8; 32]).unwrap();
    c.bench_function("ML-DSA-65 qtv-crypto/decode+verify", |b| {
        b.iter(|| qtv_crypto::ml_dsa::verify(black_box(&pk), black_box(&MSG), &sig, b""))
    });
}

fn fresh(c: &mut Criterion) {
    ml_dsa::<MlDsa44>(c, "ML-DSA-44");
    ml_dsa::<MlDsa65>(c, "ML-DSA-65");
    ml_dsa::<MlDsa87>(c, "ML-DSA-87");
    qtv(c);
    slh_dsa::<Sha2_128s>(c, "SLH-DSA-SHA2-128s");
    slh_dsa::<Sha2_128f>(c, "SLH-DSA-SHA2-128f");
    slh_dsa::<Shake128f>(c, "SLH-DSA-SHAKE-128f");
}

criterion_group!(benches, fresh);
criterion_main!(benches);
