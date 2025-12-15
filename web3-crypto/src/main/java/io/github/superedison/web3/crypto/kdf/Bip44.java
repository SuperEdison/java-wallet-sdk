package io.github.superedison.web3.crypto.kdf;

/**
 * BIP-44 多币种分层确定性钱包
 * 路径格式: m / purpose' / coin_type' / account' / change / address_index
 */
public final class Bip44 {

    // 常用 coin types (BIP-44)
    public static final int COIN_TYPE_BTC = 0;
    public static final int COIN_TYPE_BTC_TESTNET = 1;
    public static final int COIN_TYPE_LTC = 2;
    public static final int COIN_TYPE_DOGE = 3;
    public static final int COIN_TYPE_ETH = 60;
    public static final int COIN_TYPE_ETC = 61;
    public static final int COIN_TYPE_ATOM = 118;
    public static final int COIN_TYPE_TRX = 195;
    public static final int COIN_TYPE_DOT = 354;
    public static final int COIN_TYPE_SOL = 501;

    // Purpose
    public static final int PURPOSE_BIP44 = 44;
    public static final int PURPOSE_BIP49 = 49;  // P2WPKH-nested-in-P2SH
    public static final int PURPOSE_BIP84 = 84;  // Native SegWit (P2WPKH)
    public static final int PURPOSE_BIP86 = 86;  // Taproot (P2TR)

    private Bip44() {}

    /**
     * 生成 BIP-44 路径
     * @param coinType 币种类型
     * @param account 账户索引
     * @param change 0=外部地址, 1=找零地址
     * @param addressIndex 地址索引
     * @return 派生路径
     */
    public static String getPath(int coinType, int account, int change, int addressIndex) {
        return getPath(PURPOSE_BIP44, coinType, account, change, addressIndex);
    }

    /**
     * 生成指定 purpose 的路径
     */
    public static String getPath(int purpose, int coinType, int account, int change, int addressIndex) {
        return String.format("m/%d'/%d'/%d'/%d/%d",
                purpose, coinType, account, change, addressIndex);
    }

    /**
     * 获取以太坊默认路径 (m/44'/60'/0'/0/0)
     */
    public static String getEthereumPath(int addressIndex) {
        return getPath(COIN_TYPE_ETH, 0, 0, addressIndex);
    }

    /**
     * 获取比特币 BIP-84 路径 (Native SegWit)
     */
    public static String getBitcoinSegwitPath(int addressIndex) {
        return getPath(PURPOSE_BIP84, COIN_TYPE_BTC, 0, 0, addressIndex);
    }

    /**
     * 获取比特币 BIP-44 路径 (Legacy)
     */
    public static String getBitcoinLegacyPath(int addressIndex) {
        return getPath(PURPOSE_BIP44, COIN_TYPE_BTC, 0, 0, addressIndex);
    }

    /**
     * 获取比特币 BIP-86 路径 (Taproot)
     */
    public static String getBitcoinTaprootPath(int addressIndex) {
        return getPath(PURPOSE_BIP86, COIN_TYPE_BTC, 0, 0, addressIndex);
    }

    /**
     * 获取 Solana 路径 (m/44'/501'/0'/0')
     * Solana 使用硬化的地址索引
     */
    public static String getSolanaPath(int addressIndex) {
        return String.format("m/44'/%d'/%d'/%d'", COIN_TYPE_SOL, addressIndex, 0);
    }

    /**
     * 获取 TRON 路径
     */
    public static String getTronPath(int addressIndex) {
        return getPath(COIN_TYPE_TRX, 0, 0, addressIndex);
    }

    /**
     * 从种子派生指定路径的密钥
     */
    public static Bip32.ExtendedKey derive(byte[] seed, int coinType, int account, int change, int addressIndex) {
        String path = getPath(coinType, account, change, addressIndex);
        return Bip32.derivePath(seed, path);
    }

    /**
     * 从种子派生以太坊密钥
     */
    public static Bip32.ExtendedKey deriveEthereum(byte[] seed, int addressIndex) {
        return Bip32.derivePath(seed, getEthereumPath(addressIndex));
    }

    /**
     * 从种子派生比特币密钥 (SegWit)
     */
    public static Bip32.ExtendedKey deriveBitcoinSegwit(byte[] seed, int addressIndex) {
        return Bip32.derivePath(seed, getBitcoinSegwitPath(addressIndex));
    }

    /**
     * 解析路径组件
     */
    public static PathComponents parsePath(String path) {
        int[] indices = Bip32.parsePath(path);
        if (indices.length < 3) {
            throw new IllegalArgumentException("Invalid BIP-44 path: " + path);
        }

        int purpose = indices[0] & 0x7FFFFFFF;
        int coinType = indices[1] & 0x7FFFFFFF;
        int account = indices[2] & 0x7FFFFFFF;
        int change = indices.length > 3 ? indices[3] : 0;
        int addressIndex = indices.length > 4 ? indices[4] : 0;

        return new PathComponents(purpose, coinType, account, change, addressIndex);
    }

    /**
     * 路径组件
     */
    public record PathComponents(int purpose, int coinType, int account, int change, int addressIndex) {

        public String toPath() {
            return getPath(purpose, coinType, account, change, addressIndex);
        }

        /**
         * 获取下一个地址的路径
         */
        public PathComponents nextAddress() {
            return new PathComponents(purpose, coinType, account, change, addressIndex + 1);
        }

        /**
         * 获取下一个账户的路径
         */
        public PathComponents nextAccount() {
            return new PathComponents(purpose, coinType, account + 1, 0, 0);
        }
    }
}