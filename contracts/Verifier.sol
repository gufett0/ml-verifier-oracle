// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    PROOF_LEN_CPTR = 0x44;
    uint256 internal constant        PROOF_CPTR = 0x64;
    uint256 internal constant NUM_INSTANCE_CPTR = 0x0cc4;
    uint256 internal constant     INSTANCE_CPTR = 0x0ce4;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x04e4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x05a4;

    uint256 internal constant                VK_MPTR = 0x0680;
    uint256 internal constant         VK_DIGEST_MPTR = 0x0680;
    uint256 internal constant                 K_MPTR = 0x06a0;
    uint256 internal constant             N_INV_MPTR = 0x06c0;
    uint256 internal constant             OMEGA_MPTR = 0x06e0;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0700;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0720;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x0740;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x0760;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x0780;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x07a0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x07c0;
    uint256 internal constant              G1_X_MPTR = 0x07e0;
    uint256 internal constant              G1_Y_MPTR = 0x0800;
    uint256 internal constant            G2_X_1_MPTR = 0x0820;
    uint256 internal constant            G2_X_2_MPTR = 0x0840;
    uint256 internal constant            G2_Y_1_MPTR = 0x0860;
    uint256 internal constant            G2_Y_2_MPTR = 0x0880;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x08a0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x08c0;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x08e0;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0900;

    uint256 internal constant CHALLENGE_MPTR = 0x0ee0;

    uint256 internal constant THETA_MPTR = 0x0ee0;
    uint256 internal constant  BETA_MPTR = 0x0f00;
    uint256 internal constant GAMMA_MPTR = 0x0f20;
    uint256 internal constant     Y_MPTR = 0x0f40;
    uint256 internal constant     X_MPTR = 0x0f60;
    uint256 internal constant  ZETA_MPTR = 0x0f80;
    uint256 internal constant    NU_MPTR = 0x0fa0;
    uint256 internal constant    MU_MPTR = 0x0fc0;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x0fe0;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x1000;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x1020;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x1040;
    uint256 internal constant             X_N_MPTR = 0x1060;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x1080;
    uint256 internal constant          L_LAST_MPTR = 0x10a0;
    uint256 internal constant         L_BLIND_MPTR = 0x10c0;
    uint256 internal constant             L_0_MPTR = 0x10e0;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x1100;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x1120;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x1140;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x1160;
    uint256 internal constant          R_EVAL_MPTR = 0x1180;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x11a0;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x11c0;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x11e0;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x1200;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end, r) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), r)
                    all_inv := mulmod(all_inv, mload(mptr), r)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), r)
                let inv_second := mulmod(all_inv, mload(first_mptr), r)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field

            // Initialize success as true
            let success := true

            {
                // Load vk into memory
                mstore(0x0680, 0x29da08f4be13f49753623ca7148b92b17ff01e4119c85e31d8d892680b8e2e76) // vk_digest
                mstore(0x06a0, 0x000000000000000000000000000000000000000000000000000000000000000d) // k
                mstore(0x06c0, 0x3062cb506d9a969cb702833453cd4c52654aa6a93775a2c5bf57d68443608001) // n_inv
                mstore(0x06e0, 0x10e3d295c1599ff535a1bb49f23d81aa03bd0ed25881f9ed12b179af67f67ae1) // omega
                mstore(0x0700, 0x09ff38534bd08f2b08b6010aaee9ac485d3afb3a9ae4280907537b08fc6e53e5) // omega_inv
                mstore(0x0720, 0x1fe62c4a3c6640bbac666390d8ab7318a0de5374d46b2921e3217838d26470ad) // omega_inv_to_l
                mstore(0x0740, 0x0000000000000000000000000000000000000000000000000000000000000001) // num_instances
                mstore(0x0760, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x0780, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x07a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x07c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x07e0, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0800, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0820, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x0840, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x0860, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x0880, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x08a0, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
                mstore(0x08c0, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
                mstore(0x08e0, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
                mstore(0x0900, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
                mstore(0x0920, 0x083f616e1264cc3a5544386c303a778310b0e39da3c0bd0a152ff2b316a37fc2) // fixed_comms[0].x
                mstore(0x0940, 0x029db10dfa4dd50ab917169626c7bdb810be561580c46a33cf3089002fb7af6f) // fixed_comms[0].y
                mstore(0x0960, 0x27c9723119cc85dbd177d544c8ba5e58261338832a0863edb5bd5886c7733be9) // fixed_comms[1].x
                mstore(0x0980, 0x05941587b88545ae31d0b940870604af95bbdf7f993aaa156f632914503c72cf) // fixed_comms[1].y
                mstore(0x09a0, 0x1484ca31417edd15aab1d6afe793498dda27ad24097475622864dfda1dc1f63e) // fixed_comms[2].x
                mstore(0x09c0, 0x02018b2f67c3a951691aa4397c7b9c8be0b9ac0faf9e39eae9fc4fede198370e) // fixed_comms[2].y
                mstore(0x09e0, 0x2ab3b3eef83cfbfa4009a6e9020aba3546141a6f2c5286d2435066943929dd6d) // fixed_comms[3].x
                mstore(0x0a00, 0x1b04819de1b5b1b394af24202d475f41fa14dbd0d531cf14ab34069f8ddaba05) // fixed_comms[3].y
                mstore(0x0a20, 0x07addde73c3b9f7152ac6a007ecbed8e40ff1dfc9f71e677dcc0c5dacc7d8ebb) // fixed_comms[4].x
                mstore(0x0a40, 0x230bf5e13bc40e87384d33a6f3e6bcd94c410f2b217e215dc053d1c5fd354408) // fixed_comms[4].y
                mstore(0x0a60, 0x07addde73c3b9f7152ac6a007ecbed8e40ff1dfc9f71e677dcc0c5dacc7d8ebb) // fixed_comms[5].x
                mstore(0x0a80, 0x230bf5e13bc40e87384d33a6f3e6bcd94c410f2b217e215dc053d1c5fd354408) // fixed_comms[5].y
                mstore(0x0aa0, 0x12a2bbb9551ec9672dcb064993e9d9135a641b5496f823583fff9442878174f5) // fixed_comms[6].x
                mstore(0x0ac0, 0x1b21deddadef4f2739b8a8f5c453f9b75a1b7bcdaf01c5dad4b0f0c9f7196b39) // fixed_comms[6].y
                mstore(0x0ae0, 0x1cea054a57af80ba0e4920f88a6dd9098fb2e2ce3ca1ec700a1041d731aac928) // fixed_comms[7].x
                mstore(0x0b00, 0x068df755feecfa52b10e4ae0cbce435a5bfc4a8541430fee08074c4cb8d5aae5) // fixed_comms[7].y
                mstore(0x0b20, 0x150726d22b2dafb590ac61cedad141f2ee22fce67d20c3f4993f0ccdb208672b) // fixed_comms[8].x
                mstore(0x0b40, 0x17301c7f6cde43d350f2fec4cda811b56e3a02470ee82c4a6df16e29c6ce00c2) // fixed_comms[8].y
                mstore(0x0b60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[9].x
                mstore(0x0b80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[9].y
                mstore(0x0ba0, 0x1852b5bab217d5be86bffce5a0b591c74ec0974f6c410f6f4b64040ff38be000) // fixed_comms[10].x
                mstore(0x0bc0, 0x2fdff28e36fa161915ad60fe1a4f9fb66b79bec0f3a1a2f9ae307596db12cad5) // fixed_comms[10].y
                mstore(0x0be0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[11].x
                mstore(0x0c00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[11].y
                mstore(0x0c20, 0x0a0bec4f6f5f239f373a93aadd4167d330566ebf9fbafa19e1e7752e4e0b4990) // fixed_comms[12].x
                mstore(0x0c40, 0x07a173cf7d42fe38cb23a3278418cb3f6662693f2c3d1ac94a0b787f7f2927cc) // fixed_comms[12].y
                mstore(0x0c60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[13].x
                mstore(0x0c80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[13].y
                mstore(0x0ca0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[14].x
                mstore(0x0cc0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[14].y
                mstore(0x0ce0, 0x04b029dc8525054989b699b672c273da616290b0d6cb9973068aad4d88b2bd6b) // permutation_comms[0].x
                mstore(0x0d00, 0x07073da0b5d32b8e28f3571c1e6d401796e8d4e5f549fd5639d3438137b6ff14) // permutation_comms[0].y
                mstore(0x0d20, 0x0f9afe1b36ff76fa4a9400972d7fde138846571604582ab2f737f3722f71a75c) // permutation_comms[1].x
                mstore(0x0d40, 0x15a4b5bfe84e889a93d90705e8235204d719abf4ec8de98ac35ce7d3938adc9a) // permutation_comms[1].y
                mstore(0x0d60, 0x2075ba8450a8b7f9305ee6f6c9ccfbd863589697f1b62ee6b8e647a382b6e9e4) // permutation_comms[2].x
                mstore(0x0d80, 0x131c9f7c677beb877f7388df838a553249228da663f89ed35465a8260cf257fe) // permutation_comms[2].y
                mstore(0x0da0, 0x1679f24a06319be284f29710f98e95c8912e26427bacb15fd01f04856e5a980b) // permutation_comms[3].x
                mstore(0x0dc0, 0x088f368fe7629562af06286b7da18f326ed0936d2d92a2f2e2091f18b604b958) // permutation_comms[3].y
                mstore(0x0de0, 0x05d37544fd8a6d38a63e0f4c62636e3778dfcc3915715cb37e4c8d11acba4192) // permutation_comms[4].x
                mstore(0x0e00, 0x110e6a2ca56c71a0001a8a2e131dfc9cbe323535814967367f8f3fcd193e25bc) // permutation_comms[4].y
                mstore(0x0e20, 0x0e69b06be71bd57b3e3fbf28241598becd0df048eabc0dcf95e60732542ac5a4) // permutation_comms[5].x
                mstore(0x0e40, 0x12f9693f02ea4296d14783f990d5ecd620b72d959bb3f7f1879e1e0710787b1e) // permutation_comms[5].y
                mstore(0x0e60, 0x0205edb5da33a1346360937abebd4fa3d08ded9786597c9624bc65431d09cd98) // permutation_comms[6].x
                mstore(0x0e80, 0x27e198be0010330325dfb51c898ed16cb38b614da70a230c2feab119aa1d619b) // permutation_comms[6].y
                mstore(0x0ea0, 0x24f74784d986ca45383677a7cef07e1ad43a0f7018cf6614df4cd60289c97b61) // permutation_comms[7].x
                mstore(0x0ec0, 0x12dea5a69c1d440210e6ecb944a883ab8268fa6f62ca3bcedaecdb937ad72bd8) // permutation_comms[7].y

                // Check valid length of proof
                success := and(success, eq(0x0c60, calldataload(PROOF_LEN_CPTR)))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0180) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0100) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0200) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0100) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0660) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(INSTANCE_CPTR, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20), r)

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := INSTANCE_CPTR
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let delta := 4131629893567559867359510883348571134090853742863529169391034518566172092834
                let y := mload(Y_MPTR)
                {
                    let f_9 := calldataload(0x07e4)
                    let var0 := 0x1
                    let var1 := sub(r, f_9)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_9, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_4 := calldataload(0x0664)
                    let a_2 := calldataload(0x0624)
                    let var7 := sub(r, a_2)
                    let var8 := addmod(a_4, var7, r)
                    let var9 := mulmod(var6, var8, r)
                    quotient_eval_numer := var9
                }
                {
                    let f_11 := calldataload(0x0824)
                    let var0 := 0x1
                    let var1 := sub(r, f_11)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_11, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_5 := calldataload(0x0684)
                    let a_3 := calldataload(0x0644)
                    let var7 := sub(r, a_3)
                    let var8 := addmod(a_5, var7, r)
                    let var9 := mulmod(var6, var8, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var9, r)
                }
                {
                    let f_8 := calldataload(0x07c4)
                    let var0 := 0x2
                    let var1 := sub(r, f_8)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_8, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, r)
                    let var9 := mulmod(var6, var8, r)
                    let a_4 := calldataload(0x0664)
                    let a_0 := calldataload(0x05e4)
                    let a_2 := calldataload(0x0624)
                    let var10 := addmod(a_0, a_2, r)
                    let var11 := sub(r, var10)
                    let var12 := addmod(a_4, var11, r)
                    let var13 := mulmod(var9, var12, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_10 := calldataload(0x0804)
                    let var0 := 0x2
                    let var1 := sub(r, f_10)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_10, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, r)
                    let var9 := mulmod(var6, var8, r)
                    let a_5 := calldataload(0x0684)
                    let a_1 := calldataload(0x0604)
                    let a_3 := calldataload(0x0644)
                    let var10 := addmod(a_1, a_3, r)
                    let var11 := sub(r, var10)
                    let var12 := addmod(a_5, var11, r)
                    let var13 := mulmod(var9, var12, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_9 := calldataload(0x07e4)
                    let var0 := 0x2
                    let var1 := sub(r, f_9)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_9, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_4 := calldataload(0x0664)
                    let a_0 := calldataload(0x05e4)
                    let a_2 := calldataload(0x0624)
                    let var7 := mulmod(a_0, a_2, r)
                    let var8 := sub(r, var7)
                    let var9 := addmod(a_4, var8, r)
                    let var10 := mulmod(var6, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_11 := calldataload(0x0824)
                    let var0 := 0x2
                    let var1 := sub(r, f_11)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_11, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_5 := calldataload(0x0684)
                    let a_1 := calldataload(0x0604)
                    let a_3 := calldataload(0x0644)
                    let var7 := mulmod(a_1, a_3, r)
                    let var8 := sub(r, var7)
                    let var9 := addmod(a_5, var8, r)
                    let var10 := mulmod(var6, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_8 := calldataload(0x07c4)
                    let var0 := 0x1
                    let var1 := sub(r, f_8)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_8, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, r)
                    let var9 := mulmod(var6, var8, r)
                    let a_4 := calldataload(0x0664)
                    let a_0 := calldataload(0x05e4)
                    let a_2 := calldataload(0x0624)
                    let var10 := sub(r, a_2)
                    let var11 := addmod(a_0, var10, r)
                    let var12 := sub(r, var11)
                    let var13 := addmod(a_4, var12, r)
                    let var14 := mulmod(var9, var13, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_10 := calldataload(0x0804)
                    let var0 := 0x1
                    let var1 := sub(r, f_10)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_10, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, r)
                    let var9 := mulmod(var6, var8, r)
                    let a_5 := calldataload(0x0684)
                    let a_1 := calldataload(0x0604)
                    let a_3 := calldataload(0x0644)
                    let var10 := sub(r, a_3)
                    let var11 := addmod(a_1, var10, r)
                    let var12 := sub(r, var11)
                    let var13 := addmod(a_5, var12, r)
                    let var14 := mulmod(var9, var13, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_8 := calldataload(0x07c4)
                    let var0 := 0x1
                    let var1 := sub(r, f_8)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_8, var2, r)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, r)
                    let var9 := mulmod(var6, var8, r)
                    let a_4 := calldataload(0x0664)
                    let a_2 := calldataload(0x0624)
                    let var10 := sub(r, a_2)
                    let var11 := sub(r, var10)
                    let var12 := addmod(a_4, var11, r)
                    let var13 := mulmod(var9, var12, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_10 := calldataload(0x0804)
                    let var0 := 0x1
                    let var1 := sub(r, f_10)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_10, var2, r)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, r)
                    let var9 := mulmod(var6, var8, r)
                    let a_5 := calldataload(0x0684)
                    let a_3 := calldataload(0x0644)
                    let var10 := sub(r, a_3)
                    let var11 := sub(r, var10)
                    let var12 := addmod(a_5, var11, r)
                    let var13 := mulmod(var9, var12, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_8 := calldataload(0x07c4)
                    let var0 := 0x1
                    let var1 := sub(r, f_8)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_8, var2, r)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, r)
                    let var9 := mulmod(var6, var8, r)
                    let a_2 := calldataload(0x0624)
                    let var10 := mulmod(var9, a_2, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_10 := calldataload(0x0804)
                    let var0 := 0x1
                    let var1 := sub(r, f_10)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_10, var2, r)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, r)
                    let var9 := mulmod(var6, var8, r)
                    let a_3 := calldataload(0x0644)
                    let var10 := mulmod(var9, a_3, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_9 := calldataload(0x07e4)
                    let var0 := 0x1
                    let var1 := sub(r, f_9)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_9, var2, r)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_2 := calldataload(0x0624)
                    let var7 := sub(r, var0)
                    let var8 := addmod(a_2, var7, r)
                    let var9 := mulmod(a_2, var8, r)
                    let var10 := mulmod(var6, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_11 := calldataload(0x0824)
                    let var0 := 0x1
                    let var1 := sub(r, f_11)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_11, var2, r)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_3 := calldataload(0x0644)
                    let var7 := sub(r, var0)
                    let var8 := addmod(a_3, var7, r)
                    let var9 := mulmod(a_3, var8, r)
                    let var10 := mulmod(var6, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_12 := calldataload(0x0844)
                    let var0 := 0x1
                    let var1 := sub(r, f_12)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_12, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_4 := calldataload(0x0664)
                    let a_4_prev_1 := calldataload(0x06a4)
                    let var7 := 0x0
                    let a_0 := calldataload(0x05e4)
                    let a_2 := calldataload(0x0624)
                    let var8 := mulmod(a_0, a_2, r)
                    let var9 := addmod(var7, var8, r)
                    let a_1 := calldataload(0x0604)
                    let a_3 := calldataload(0x0644)
                    let var10 := mulmod(a_1, a_3, r)
                    let var11 := addmod(var9, var10, r)
                    let var12 := addmod(a_4_prev_1, var11, r)
                    let var13 := sub(r, var12)
                    let var14 := addmod(a_4, var13, r)
                    let var15 := mulmod(var6, var14, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_12 := calldataload(0x0844)
                    let var0 := 0x2
                    let var1 := sub(r, f_12)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_12, var2, r)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_4 := calldataload(0x0664)
                    let var7 := 0x0
                    let a_0 := calldataload(0x05e4)
                    let a_2 := calldataload(0x0624)
                    let var8 := mulmod(a_0, a_2, r)
                    let var9 := addmod(var7, var8, r)
                    let a_1 := calldataload(0x0604)
                    let a_3 := calldataload(0x0644)
                    let var10 := mulmod(a_1, a_3, r)
                    let var11 := addmod(var9, var10, r)
                    let var12 := sub(r, var11)
                    let var13 := addmod(a_4, var12, r)
                    let var14 := mulmod(var6, var13, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_12 := calldataload(0x0844)
                    let var0 := 0x1
                    let var1 := sub(r, f_12)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_12, var2, r)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, r)
                    let var6 := mulmod(var3, var5, r)
                    let a_4 := calldataload(0x0664)
                    let a_2 := calldataload(0x0624)
                    let var7 := mulmod(var0, a_2, r)
                    let a_3 := calldataload(0x0644)
                    let var8 := mulmod(var7, a_3, r)
                    let var9 := sub(r, var8)
                    let var10 := addmod(a_4, var9, r)
                    let var11 := mulmod(var6, var10, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_13 := calldataload(0x0864)
                    let var0 := 0x2
                    let var1 := sub(r, f_13)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_13, var2, r)
                    let a_4 := calldataload(0x0664)
                    let a_4_prev_1 := calldataload(0x06a4)
                    let var4 := 0x1
                    let a_2 := calldataload(0x0624)
                    let var5 := mulmod(var4, a_2, r)
                    let a_3 := calldataload(0x0644)
                    let var6 := mulmod(var5, a_3, r)
                    let var7 := mulmod(a_4_prev_1, var6, r)
                    let var8 := sub(r, var7)
                    let var9 := addmod(a_4, var8, r)
                    let var10 := mulmod(var3, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_14 := calldataload(0x0884)
                    let a_4 := calldataload(0x0664)
                    let var0 := 0x0
                    let a_2 := calldataload(0x0624)
                    let var1 := addmod(var0, a_2, r)
                    let a_3 := calldataload(0x0644)
                    let var2 := addmod(var1, a_3, r)
                    let var3 := sub(r, var2)
                    let var4 := addmod(a_4, var3, r)
                    let var5 := mulmod(f_14, var4, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var5, r)
                }
                {
                    let f_13 := calldataload(0x0864)
                    let var0 := 0x1
                    let var1 := sub(r, f_13)
                    let var2 := addmod(var0, var1, r)
                    let var3 := mulmod(f_13, var2, r)
                    let a_4 := calldataload(0x0664)
                    let a_4_prev_1 := calldataload(0x06a4)
                    let var4 := 0x0
                    let a_2 := calldataload(0x0624)
                    let var5 := addmod(var4, a_2, r)
                    let a_3 := calldataload(0x0644)
                    let var6 := addmod(var5, a_3, r)
                    let var7 := addmod(a_4_prev_1, var6, r)
                    let var8 := sub(r, var7)
                    let var9 := addmod(a_4, var8, r)
                    let var10 := mulmod(var3, var9, r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(r, mulmod(l_0, calldataload(0x09c4), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x0a84)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, r), sub(r, perm_z_last), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0a24), sub(r, calldataload(0x0a04)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x0a84), sub(r, calldataload(0x0a64)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x09e4)
                    let rhs := calldataload(0x09c4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x05e4), mulmod(beta, calldataload(0x08c4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0604), mulmod(beta, calldataload(0x08e4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0624), mulmod(beta, calldataload(0x0904), r), r), gamma, r), r)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x05e4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0604), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0624), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0a44)
                    let rhs := calldataload(0x0a24)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0644), mulmod(beta, calldataload(0x0924), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0664), mulmod(beta, calldataload(0x0944), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0684), mulmod(beta, calldataload(0x0964), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0644), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0664), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0684), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0aa4)
                    let rhs := calldataload(0x0a84)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x06c4), mulmod(beta, calldataload(0x0984), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x09a4), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x06c4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), r), gamma, r), r)
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0ac4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0ac4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x06e4)
                        let f_2 := calldataload(0x0704)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_2, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_4 := calldataload(0x0744)
                        let var0 := 0x1
                        let var1 := mulmod(f_4, var0, r)
                        let a_0 := calldataload(0x05e4)
                        let var2 := mulmod(var1, a_0, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffc7
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_2 := calldataload(0x0624)
                        let var8 := mulmod(var1, a_2, r)
                        let var9 := 0x3a
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x0b04), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x0ae4), sub(r, calldataload(0x0ac4)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0b24), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0b24), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x06e4)
                        let f_2 := calldataload(0x0704)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_2, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_5 := calldataload(0x0764)
                        let var0 := 0x1
                        let var1 := mulmod(f_5, var0, r)
                        let a_1 := calldataload(0x0604)
                        let var2 := mulmod(var1, a_1, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffc7
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_3 := calldataload(0x0644)
                        let var8 := mulmod(var1, a_3, r)
                        let var9 := 0x3a
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x0b64), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x0b44), sub(r, calldataload(0x0b24)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0b84), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0b84), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x06e4)
                        let f_3 := calldataload(0x0724)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_3, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_6 := calldataload(0x0784)
                        let var0 := 0x1
                        let var1 := mulmod(f_6, var0, r)
                        let a_0 := calldataload(0x05e4)
                        let var2 := mulmod(var1, a_0, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffc7
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_2 := calldataload(0x0624)
                        let var8 := mulmod(var1, a_2, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x0bc4), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x0ba4), sub(r, calldataload(0x0b84)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0be4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0be4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x06e4)
                        let f_3 := calldataload(0x0724)
                        table := f_1
                        table := addmod(mulmod(table, theta, r), f_3, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x07a4)
                        let var0 := 0x1
                        let var1 := mulmod(f_7, var0, r)
                        let a_1 := calldataload(0x0604)
                        let var2 := mulmod(var1, a_1, r)
                        let var3 := sub(r, var1)
                        let var4 := addmod(var0, var3, r)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffc7
                        let var6 := mulmod(var4, var5, r)
                        let var7 := addmod(var2, var6, r)
                        let a_3 := calldataload(0x0644)
                        let var8 := mulmod(var1, a_3, r)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, r)
                        let var11 := addmod(var8, var10, r)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, r), var11, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x0c24), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x0c04), sub(r, calldataload(0x0be4)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)
                pop(delta)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, r)
                    mstore(0x0360, x_pow_of_omega)
                    mstore(0x0340, x)
                    x_pow_of_omega := mulmod(x, omega_inv, r)
                    mstore(0x0320, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    mstore(0x0300, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x0380
                            let mptr_end := 0x0400
                            let point_mptr := 0x0300
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(r, mload(point_mptr)), r))
                    }
                    let s
                    s := mload(0x03c0)
                    mstore(0x0400, s)
                    let diff
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), r)
                    diff := mulmod(diff, mload(0x03e0), r)
                    mstore(0x0420, diff)
                    mstore(0x00, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03e0), r)
                    mstore(0x0440, diff)
                    diff := mload(0x03a0)
                    mstore(0x0460, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), r)
                    mstore(0x0480, diff)
                }
                {
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x03c0), r)
                    mstore(0x20, coeff)
                }
                {
                    let point_1 := mload(0x0320)
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := addmod(point_1, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x03a0), r)
                    mstore(0x40, coeff)
                    coeff := addmod(point_2, sub(r, point_1), r)
                    coeff := mulmod(coeff, mload(0x03c0), r)
                    mstore(0x60, coeff)
                }
                {
                    let point_0 := mload(0x0300)
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_0, sub(r, point_2), r)
                    coeff := mulmod(coeff, addmod(point_0, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x0380), r)
                    mstore(0x80, coeff)
                    coeff := addmod(point_2, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_3), r), r)
                    coeff := mulmod(coeff, mload(0x03c0), r)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_3, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_3, sub(r, point_2), r), r)
                    coeff := mulmod(coeff, mload(0x03e0), r)
                    mstore(0xc0, coeff)
                }
                {
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_2, sub(r, point_3), r)
                    coeff := mulmod(coeff, mload(0x03c0), r)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_3, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x03e0), r)
                    mstore(0x0100, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0120, r)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0420, diff_0_inv)
                    for
                        {
                            let mptr := 0x0440
                            let mptr_end := 0x04a0
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, r))
                    }
                }
                {
                    let coeff := mload(0x20)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x08a4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), r), r)
                    for
                        {
                            let mptr := 0x09a4
                            let mptr_end := 0x08a4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    for
                        {
                            let mptr := 0x0884
                            let mptr_end := 0x06a4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0c24), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0bc4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0b64), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0b04), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0684), r), r)
                    for
                        {
                            let mptr := 0x0644
                            let mptr_end := 0x05c4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    mstore(0x04a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x06a4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0664), r), r)
                    r_eval := mulmod(r_eval, mload(0x0440), r)
                    mstore(0x04c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0a64), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0a24), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0a44), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0a04), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x09c4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x09e4), r), r)
                    r_eval := mulmod(r_eval, mload(0x0460), r)
                    mstore(0x04e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0be4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0c04), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0b84), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0ba4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0b24), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0b44), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0ac4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0ae4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x0a84), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x0aa4), r), r)
                    r_eval := mulmod(r_eval, mload(0x0480), r)
                    mstore(0x0500, r_eval)
                }
                {
                    let sum := mload(0x20)
                    mstore(0x0520, sum)
                }
                {
                    let sum := mload(0x40)
                    sum := addmod(sum, mload(0x60), r)
                    mstore(0x0540, sum)
                }
                {
                    let sum := mload(0x80)
                    sum := addmod(sum, mload(0xa0), r)
                    sum := addmod(sum, mload(0xc0), r)
                    mstore(0x0560, sum)
                }
                {
                    let sum := mload(0xe0)
                    sum := addmod(sum, mload(0x0100), r)
                    mstore(0x0580, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0x80
                            let sum_mptr := 0x0520
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x80, r)
                    let r_eval := mulmod(mload(0x60), mload(0x0500), r)
                    for
                        {
                            let sum_inv_mptr := 0x40
                            let sum_inv_mptr_end := 0x80
                            let r_eval_mptr := 0x04e0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), r)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), r), r)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x04a4))
                    mstore(0x20, calldataload(0x04c4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x0ea0
                            let mptr_end := 0x08e0
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x02a4
                            let mptr_end := 0x0164
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0124
                            let mptr_end := 0x24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    mstore(0x80, calldataload(0x0164))
                    mstore(0xa0, calldataload(0x0184))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0440), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x0324))
                    mstore(0xa0, calldataload(0x0344))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x02e4), calldataload(0x0304))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0460), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x0464))
                    mstore(0xa0, calldataload(0x0484))
                    for
                        {
                            let mptr := 0x0424
                            let mptr_end := 0x0324
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0480), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(r, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x0c44))
                    mstore(0xa0, calldataload(0x0c64))
                    success := ec_mul_tmp(success, sub(r, mload(0x0400)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x0c84))
                    mstore(0xa0, calldataload(0x0ca4))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x0c84))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x0ca4))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}