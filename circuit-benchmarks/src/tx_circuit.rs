//! Tx circuit benchmarks

#[cfg(test)]
mod tests {
    use crate::bench_params::DEGREE;
    use ark_std::{end_timer, start_timer};
    use eth_types::geth_types::Transaction;
    use ethers_core::{
        types::{NameOrAddress, TransactionRequest},
        utils::keccak256,
    };
    use ethers_signers::{LocalWallet, Signer};
    use group::{Curve, Group};
    use halo2_proofs::arithmetic::{CurveAffine, Field};
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::{
        pairing::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::{Params, ParamsVerifier},
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use rand::{CryptoRng, Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use secp256k1::Secp256k1Affine;
    use std::marker::PhantomData;
    use zkevm_circuits::tx_circuit::{sign_verify::SignVerifyChip, TxCircuit};

    fn rand_tx<R: Rng + CryptoRng>(mut rng: R, chain_id: u64) -> Transaction {
        let wallet0 = LocalWallet::new(&mut rng).with_chain_id(chain_id);
        let wallet1 = LocalWallet::new(&mut rng).with_chain_id(chain_id);
        let from = wallet0.address();
        let to = wallet1.address();
        let data = b"hello";
        let tx = TransactionRequest::new()
            .from(from)
            .to(to)
            .nonce(3)
            .value(1000)
            .data(data)
            .gas(500_000)
            .gas_price(1234);
        let tx_rlp = tx.rlp(chain_id);
        let sighash = keccak256(tx_rlp.as_ref()).into();
        let sig = wallet0.sign_hash(sighash, true);
        let to = tx.to.map(|to| match to {
            NameOrAddress::Address(a) => a,
            _ => unreachable!(),
        });
        Transaction {
            from: tx.from.unwrap(),
            to,
            gas_limit: tx.gas.unwrap(),
            gas_price: tx.gas_price.unwrap(),
            value: tx.value.unwrap(),
            call_data: tx.data.unwrap(),
            nonce: tx.nonce.unwrap(),
            v: sig.v,
            r: sig.r,
            s: sig.s,
            ..Transaction::default()
        }
    }

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_tx_circuit_prover() {
        // Approximate value, adjust with changes on the TxCircuit.
        const ROWS_PER_TX: usize = 175_000;
        const MAX_TXS: usize = 2_usize.pow(DEGREE as u32) / ROWS_PER_TX;
        const MAX_CALLDATA: usize = 1024;

        const NUM_TXS: usize = MAX_TXS;

        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let aux_generator =
            <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();
        let chain_id: u64 = 1337;
        let mut txs = Vec::new();
        for _ in 0..NUM_TXS {
            txs.push(rand_tx(&mut rng, chain_id));
        }

        let randomness = Fr::random(&mut rng);
        let circuit = TxCircuit::<Fr, MAX_TXS, MAX_CALLDATA> {
            sign_verify: SignVerifyChip {
                aux_generator,
                window_size: 2,
                _marker: PhantomData,
            },
            randomness,
            txs,
            chain_id,
        };

        // Bench setup generation
        let setup_message = format!(
            "Setup generation with degree = {} (MAX_TXS = {})",
            DEGREE, MAX_TXS
        );
        let start1 = start_timer!(|| setup_message);
        let general_params: Params<G1Affine> =
            Params::<G1Affine>::unsafe_setup::<Bn256>(DEGREE.try_into().unwrap());
        let verifier_params: ParamsVerifier<Bn256> = general_params.verifier(DEGREE * 2).unwrap();
        end_timer!(start1);

        // Initialize the proving key
        let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
        // Create a proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("State Proof generation with {} degree", DEGREE);
        let start2 = start_timer!(|| proof_message);
        create_proof(
            &general_params,
            &pk,
            &[circuit],
            &[&[]],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        // Bench verification time
        let start3 = start_timer!(|| "State Proof verification");
        let mut verifier_transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleVerifier::new(&verifier_params);

        verify_proof(
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[&[]],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }
}
