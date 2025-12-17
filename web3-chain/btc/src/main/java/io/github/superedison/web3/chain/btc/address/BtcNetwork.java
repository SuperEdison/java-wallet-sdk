package io.github.superedison.web3.chain.btc.address;

/**
 * Bitcoin 网络类型
 */
public enum BtcNetwork {

    /**
     * 主网
     */
    MAINNET("bc", (byte) 0x00, (byte) 0x05),

    /**
     * 测试网
     */
    TESTNET("tb", (byte) 0x6f, (byte) 0xc4),

    /**
     * Regtest（本地测试）
     */
    REGTEST("bcrt", (byte) 0x6f, (byte) 0xc4);

    private final String bech32Hrp;
    private final byte p2pkhVersion;
    private final byte p2shVersion;

    BtcNetwork(String bech32Hrp, byte p2pkhVersion, byte p2shVersion) {
        this.bech32Hrp = bech32Hrp;
        this.p2pkhVersion = p2pkhVersion;
        this.p2shVersion = p2shVersion;
    }

    /**
     * 获取 Bech32 Human Readable Part
     */
    public String getBech32Hrp() {
        return bech32Hrp;
    }

    /**
     * 获取 P2PKH 地址版本前缀
     */
    public byte getP2pkhVersion() {
        return p2pkhVersion;
    }

    /**
     * 获取 P2SH 地址版本前缀
     */
    public byte getP2shVersion() {
        return p2shVersion;
    }

    /**
     * 根据地址推断网络
     */
    public static BtcNetwork fromAddress(String address) {
        if (address == null || address.isEmpty()) {
            return null;
        }
        if (address.startsWith("bc1") || address.startsWith("1") || address.startsWith("3")) {
            return MAINNET;
        }
        if (address.startsWith("tb1") || address.startsWith("m") || address.startsWith("n") || address.startsWith("2")) {
            return TESTNET;
        }
        if (address.startsWith("bcrt1")) {
            return REGTEST;
        }
        return null;
    }
}
