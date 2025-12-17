package io.github.superedison.web3.chain.spi;

/**
 * 链类型枚举
 */
public enum ChainType {

    EVM("secp256k1", "m/44'/60'/0'/0/0"),
    BTC("secp256k1", "m/84'/0'/0'/0/0"),
    SOL("ed25519", "m/44'/501'/0'/0'"),
    APTOS("ed25519", "m/44'/637'/0'/0'/0'"),
    TRON("secp256k1", "m/44'/195'/0'/0/0"),
    COSMOS("secp256k1", "m/44'/118'/0'/0/0"),
    NEAR("ed25519", "m/44'/397'/0'");

    private final String curve;
    private final String defaultPath;

    ChainType(String curve, String defaultPath) {
        this.curve = curve;
        this.defaultPath = defaultPath;
    }

    public String getCurve() {
        return curve;
    }

    public String getDefaultPath() {
        return defaultPath;
    }

    public boolean isSecp256k1() {
        return "secp256k1".equals(curve);
    }

    public boolean isEd25519() {
        return "ed25519".equals(curve);
    }
}