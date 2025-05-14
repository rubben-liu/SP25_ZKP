// Credit Sismo: https://github.com/sismo-core/hydra-s1-zkps/blob/main/circuits/common/verify-merkle-path.circom
// Highly inspired from tornado cash https://github.com/tornadocash/tornado-core/tree/master/circuits
pragma circom 2.0.0;

include "../circom-ecdsa/circuits/ecdsa.circom";
include "../circom-ecdsa/circuits/zk-identity/eth.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
//include "../node_modules/circomlib/circuits/bitify.circom";
//include "../node_modules/circomlib/circuits/comparators.circom";

// if s == 0 returns [in[0], in[1]]
// if s == 1 returns [in[1], in[0]]
template PositionSwitcher() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}


// Verifies that merkle path is correct for a given merkle root and leaf
// pathIndices input is an array of 0/1 selectors telling whether given 
// pathElement is on the left or right side of merkle path
template VerifyMerklePath(n, k, levels) {
    signal input R[k];
    signal input S[k];
    signal input PubKey[2][k];
    signal input msghash[k];

    signal input root;
    signal input threshold;
    signal input userStars;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component ecdsaCheck = ECDSAVerifyNoPubkeyCheck(64, 4);
    ecdsaCheck.r <== R;
    ecdsaCheck.s <== S;
    ecdsaCheck.msghash <== msghash;
    ecdsaCheck.pubkey <== PubKey;

    ecdsaCheck.result === 1;
    component flattenPub = FlattenPubkey(n, k);
    for (var i = 0; i < k; i++) {
        flattenPub.chunkedPubkey[0][i] <== PubKey[0][i];
        flattenPub.chunkedPubkey[1][i] <== PubKey[1][i];
    }

    component pubToAddr = PubkeyToAddress();
    for (var i = 0; i < 512; i++) {
        pubToAddr.pubkeyBits[i] <== flattenPub.pubkeyBits[i];
    }

    component gt = GreaterThan(32);
    gt.in[0] <== userStars;
    gt.in[1] <== threshold;
    gt.out === 1;

    component selectors[levels + 1];
    component hashers[levels + 1];

    log("pubToAddr.address", pubToAddr.address);

    hashers[0] = Poseidon(1);
    hashers[0].inputs[0] <== pubToAddr.address;

    for (var i = 1; i <= levels; i++) {
        selectors[i] = PositionSwitcher();
        selectors[i].in[1] <== hashers[i - 1].out;
        selectors[i].in[0] <== pathElements[i - 1];
        selectors[i].s <== pathIndices[i - 1];

        log("in1: ", selectors[i].in[0]);
        log("in2: ", selectors[i].in[1]);
        log("s: ", selectors[i].s);
        log("out1: ", selectors[i].out[0]);
        log("out2: ", selectors[i].out[1]);

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];

        log("Computed level: ", hashers[i].out);
    }

    log("Expected merkleRoot: ", root);

    //component test;
    //test = Poseidon(2);
    //test.inputs[0] <== 1881250565452245586419841192852671026212652849919648586297501678806682883737;
    //test.inputs[1] <== 4015195612501363030418243364470313104569213676969076048159807707729185821924;
    //log("test: ", test.out);
    log("0", pathElements[0]);

    root === hashers[levels].out;
}

component main{public[root, threshold]} = VerifyMerklePath(64, 4, 3);