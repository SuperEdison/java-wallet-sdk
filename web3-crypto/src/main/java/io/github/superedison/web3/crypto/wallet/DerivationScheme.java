package io.github.superedison.web3.crypto.wallet;

/**
 * 密钥派生方案
 *
 * 不同区块链使用不同的椭圆曲线和派生标准：
 * - BIP-32 用于 secp256k1 曲线（EVM, TRON, BTC 等）
 * - SLIP-10 用于 Ed25519 曲线（Solana, NEAR, Aptos 等）
 */
public enum DerivationScheme {

    /**
     * BIP-32 派生 + secp256k1 曲线
     * 用于: EVM, TRON, BTC, LTC, BCH 等
     */
    BIP32_SECP256K1("secp256k1"),

    /**
     * SLIP-10 派生 + Ed25519 曲线
     * 用于: Solana, NEAR, Aptos, Polkadot 等
     * 注意: 只支持硬化派生
     */
    SLIP10_ED25519("ed25519");

    private final String curve;

    DerivationScheme(String curve) {
        this.curve = curve;
    }

    /**
     * 获取曲线名称
     */
    public String getCurve() {
        return curve;
    }

    /**
     * 是否为 secp256k1 曲线
     */
    public boolean isSecp256k1() {
        return this == BIP32_SECP256K1;
    }

    /**
     * 是否为 Ed25519 曲线
     */
    public boolean isEd25519() {
        return this == SLIP10_ED25519;
    }
}
