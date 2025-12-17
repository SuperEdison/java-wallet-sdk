package io.github.superedison.web3.chain.btc.address;

/**
 * Bitcoin 地址类型枚举
 */
public enum BtcAddressType {

    /**
     * Legacy P2PKH (Pay to Public Key Hash)
     * 以 '1' 开头的地址
     * BIP-44 路径: m/44'/0'/0'/0/0
     */
    P2PKH("Legacy P2PKH", "1", (byte) 0x00, (byte) 0x6f),

    /**
     * Wrapped SegWit P2SH-P2WPKH (Pay to Script Hash wrapping P2WPKH)
     * 以 '3' 开头的地址
     * BIP-49 路径: m/49'/0'/0'/0/0
     */
    P2SH_P2WPKH("Wrapped SegWit", "3", (byte) 0x05, (byte) 0xc4),

    /**
     * Native SegWit P2WPKH (Pay to Witness Public Key Hash)
     * 以 'bc1q' 开头的地址
     * BIP-84 路径: m/84'/0'/0'/0/0
     */
    P2WPKH("Native SegWit P2WPKH", "bc1q", null, null),

    /**
     * Native SegWit P2WSH (Pay to Witness Script Hash)
     * 以 'bc1q' 开头的地址（但更长）
     * 主要用于多签
     */
    P2WSH("Native SegWit P2WSH", "bc1q", null, null),

    /**
     * Taproot P2TR (Pay to Taproot)
     * 以 'bc1p' 开头的地址
     * BIP-86 路径: m/86'/0'/0'/0/0
     */
    P2TR("Taproot", "bc1p", null, null);

    private final String displayName;
    private final String prefix;
    private final Byte mainnetVersion;
    private final Byte testnetVersion;

    BtcAddressType(String displayName, String prefix, Byte mainnetVersion, Byte testnetVersion) {
        this.displayName = displayName;
        this.prefix = prefix;
        this.mainnetVersion = mainnetVersion;
        this.testnetVersion = testnetVersion;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getPrefix() {
        return prefix;
    }

    public Byte getMainnetVersion() {
        return mainnetVersion;
    }

    public Byte getTestnetVersion() {
        return testnetVersion;
    }

    /**
     * 是否使用 Bech32 编码
     */
    public boolean isBech32() {
        return this == P2WPKH || this == P2WSH || this == P2TR;
    }

    /**
     * 是否使用 Bech32m 编码（Taproot）
     */
    public boolean isBech32m() {
        return this == P2TR;
    }

    /**
     * 是否是 SegWit 地址
     */
    public boolean isSegWit() {
        return this == P2SH_P2WPKH || this == P2WPKH || this == P2WSH || this == P2TR;
    }

    /**
     * 根据地址前缀推断地址类型
     */
    public static BtcAddressType fromAddress(String address) {
        if (address == null || address.isEmpty()) {
            return null;
        }
        if (address.startsWith("bc1p") || address.startsWith("tb1p")) {
            return P2TR;
        }
        if (address.startsWith("bc1q") || address.startsWith("tb1q")) {
            // 根据长度区分 P2WPKH 和 P2WSH
            // P2WPKH: 42 字符 (mainnet), P2WSH: 62 字符 (mainnet)
            if (address.length() == 42 || address.length() == 43) {
                return P2WPKH;
            }
            return P2WSH;
        }
        if (address.startsWith("1") || address.startsWith("m") || address.startsWith("n")) {
            return P2PKH;
        }
        if (address.startsWith("3") || address.startsWith("2")) {
            return P2SH_P2WPKH;
        }
        return null;
    }
}
