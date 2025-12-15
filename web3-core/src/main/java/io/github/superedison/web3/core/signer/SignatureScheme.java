package io.github.superedison.web3.core.signer;

/**
 * 签名算法类型
 */
public enum SignatureScheme {

    /**
     * ECDSA secp256k1 (ETH, BTC)
     */
    ECDSA_SECP256K1,

    /**
     * Ed25519 (SOL, NEAR, APTOS)
     */
    ED25519,

    /**
     * Schnorr secp256k1 (BTC Taproot)
     */
    SCHNORR_SECP256K1,

    /**
     * Sr25519 (Polkadot)
     */
    SR25519
}