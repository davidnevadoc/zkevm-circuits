//! Tx circuit benchmarks

#[cfg(test)]
mod tests {
    use crate::bench_params::DEGREE;
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::{
        pairing::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::{Params, ParamsVerifier},
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use zkevm_circuits::tx_circuit::TxCircuit;

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_tx_circuit_prover() {
        // Approximate value, adjust with changes on the TxCircuit.
        const ROWS_PER_TX: usize = 175_000;
        const MAX_TXS: usize = 2_usize.pow(DEGREE as u32) / ROWS_PER_TX;
        const MAX_CALLDATA: usize = 1024;
        let empty_circuit = TxCircuit::<Fr, MAX_TXS, MAX_CALLDATA>::default();

        // Initialize the polynomial commitment parameters
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

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
        let vk = keygen_vk(&general_params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&general_params, vk, &empty_circuit).expect("keygen_pk should not fail");
        // Create a proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("State Proof generation with {} degree", DEGREE);
        let start2 = start_timer!(|| proof_message);
        create_proof(
            &general_params,
            &pk,
            &[empty_circuit],
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
