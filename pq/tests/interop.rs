use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed, Signature};
use qtv_crypto::ml_dsa as q;

fn seed(i: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s.iter_mut()
        .enumerate()
        .for_each(|(j, b)| *b = i.wrapping_mul(31).wrapping_add(j as u8));
    s
}

#[test]
fn qtv_crypto_and_rustcrypto_agree_on_ml_dsa_65() {
    for i in 0..64u8 {
        let xi = seed(i);
        let rc = ExpandedSigningKey::<MlDsa65>::from_seed(&Seed::from(xi));
        let rc_vk = rc.verifying_key();
        let (q_pk, q_sk) = q::keygen(&xi);
        assert_eq!(rc_vk.encode().as_slice(), &q_pk[..], "public key, seed {i}");

        for ctx in [&b""[..], &b"midnight/utxo-spend"[..]] {
            let msg = [i; 32];
            let rc_sig = rc.sign_deterministic(&msg, ctx).unwrap();
            let q_sig = q::sign(&q_sk, &msg, ctx, &[0u8; 32]).unwrap();
            assert_eq!(
                rc_sig.encode().as_slice(),
                &q_sig[..],
                "deterministic signature, seed {i}"
            );

            assert!(q::verify(&q_pk, &msg, &rc_sig.encode().into(), ctx));
            let parsed = Signature::<MlDsa65>::try_from(&q_sig[..]).unwrap();
            assert!(rc_vk.verify_with_context(&msg, ctx, &parsed));

            let mut other = msg;
            other[0] ^= 1;
            assert!(!q::verify(&q_pk, &other, &q_sig, ctx));
            assert!(!rc_vk.verify_with_context(&other, ctx, &parsed));
        }
    }
}
