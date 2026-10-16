use criterion::{criterion_group, criterion_main, Criterion};
use ml_dsa::{Keypair, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed, SigningKey};
use slh_dsa::{ParameterSet, Sha2_128f, Sha2_128s, Shake128f};
use std::hint::black_box;
use std::time::Duration;

const MSG: [u8; 32] = [0x5a; 32];

fn ml_dsa<P: MlDsaParams>(c: &mut Criterion, name: &str) {
    let sk = SigningKey::<P>::from_seed(&Seed::from([7u8; 32]));
    let vk = sk.verifying_key();
    let sig = ml_dsa::Signer::sign(&sk, &MSG);
    println!("{name} pk={} sig={}", vk.encode().len(), sig.encode().len());
    let msgs: Vec<[u8; 32]> = (0..1024u32)
        .map(|i| {
            let mut m = MSG;
            m[..4].copy_from_slice(&i.to_le_bytes());
            m
        })
        .collect();
    let mut i = 0usize;
    c.bench_function(&format!("{name}/sign"), |b| {
        b.iter(|| {
            i = (i + 1) % msgs.len();
            ml_dsa::Signer::sign(&sk, black_box(&msgs[i]))
        })
    });
    c.bench_function(&format!("{name}/verify"), |b| {
        b.iter(|| ml_dsa::Verifier::verify(&vk, black_box(&MSG), &sig).unwrap())
    });
}

fn slh_dsa<P: ParameterSet>(c: &mut Criterion, name: &str) {
    let sk = slh_dsa::SigningKey::<P>::new(&mut rand::rngs::OsRng);
    let vk: slh_dsa::VerifyingKey<P> = AsRef::<slh_dsa::VerifyingKey<P>>::as_ref(&sk).clone();
    let sig: slh_dsa::Signature<P> = slh_dsa::signature::Signer::sign(&sk, &MSG);
    let sig_len = slh_dsa::signature::SignatureEncoding::to_bytes(&sig).len();
    println!("{name} pk={} sig={}", vk.to_bytes().len(), sig_len);
    let mut g = c.benchmark_group(name);
    g.sample_size(10).measurement_time(Duration::from_secs(20));
    g.bench_function("sign", |b| {
        b.iter(|| slh_dsa::signature::Signer::<slh_dsa::Signature<P>>::sign(&sk, black_box(&MSG)))
    });
    g.bench_function("verify", |b| {
        b.iter(|| slh_dsa::signature::Verifier::verify(&vk, black_box(&MSG), &sig).unwrap())
    });
    g.finish();
}

fn keygen_ml_dsa_65(c: &mut Criterion) {
    c.bench_function("ML-DSA-65/keygen (RustCrypto)", |b| {
        b.iter(|| {
            SigningKey::<MlDsa65>::from_seed(black_box(&Seed::from([7u8; 32]))).verifying_key()
        })
    });
    c.bench_function("ML-DSA-65/keygen (qtv-crypto)", |b| {
        b.iter(|| qtv_crypto::ml_dsa::keygen(black_box(&[7u8; 32])))
    });
}

fn qtv_ml_dsa_65(c: &mut Criterion) {
    use qtv_crypto::ml_dsa as q;
    let (pk, sk) = q::keygen(&[7u8; 32]);
    let msgs: Vec<[u8; 32]> = (0..1024u32)
        .map(|i| {
            let mut m = MSG;
            m[..4].copy_from_slice(&i.to_le_bytes());
            m
        })
        .collect();
    let sig = q::sign(&sk, &MSG, b"", &[0u8; 32]).unwrap();
    println!("ML-DSA-65 qtv-crypto pk={} sig={}", pk.len(), sig.len());
    let mut i = 0usize;
    c.bench_function("ML-DSA-65/sign (qtv-crypto)", |b| {
        b.iter(|| {
            i = (i + 1) % msgs.len();
            q::sign(&sk, black_box(&msgs[i]), b"", &[0u8; 32])
        })
    });
    c.bench_function("ML-DSA-65/verify (qtv-crypto)", |b| {
        b.iter(|| q::verify(&pk, black_box(&MSG), &sig, b""))
    });
}

fn costs(c: &mut Criterion) {
    keygen_ml_dsa_65(c);
    qtv_ml_dsa_65(c);
    ml_dsa::<MlDsa44>(c, "ML-DSA-44");
    ml_dsa::<MlDsa65>(c, "ML-DSA-65");
    ml_dsa::<MlDsa87>(c, "ML-DSA-87");
    slh_dsa::<Sha2_128s>(c, "SLH-DSA-SHA2-128s");
    slh_dsa::<Sha2_128f>(c, "SLH-DSA-SHA2-128f");
    slh_dsa::<Shake128f>(c, "SLH-DSA-SHAKE-128f");
}

criterion_group!(benches, costs);
criterion_main!(benches);
