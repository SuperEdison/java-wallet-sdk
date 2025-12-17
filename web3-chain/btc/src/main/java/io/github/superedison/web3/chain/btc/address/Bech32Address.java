package io.github.superedison.web3.chain.btc.address;

import io.github.superedison.web3.chain.exception.AddressException;

/**
 * Bitcoin Native SegWit 地址（Bech32）
 *
 * 支持 P2WPKH 和 P2WSH:
 * - P2WPKH: 20 字节 witness program (主网 bc1q..., 42字符)
 * - P2WSH: 32 字节 witness program (主网 bc1q..., 62字符)
 *
 * BIP-84 路径 (P2WPKH): m/84'/0'/0'/0/0
 */
public final class Bech32Address extends BtcAddress {

    private static final int P2WPKH_PROGRAM_LENGTH = 20;
    private static final int P2WSH_PROGRAM_LENGTH = 32;

    private final int witnessVersion;

    private Bech32Address(byte[] witnessProgram, BtcNetwork network, BtcAddressType type, int witnessVersion) {
        super(witnessProgram, network, type);
        this.witnessVersion = witnessVersion;
    }

    /**
     * 从公钥创建 P2WPKH 地址
     */
    public static Bech32Address p2wpkhFromPublicKey(byte[] publicKey, BtcNetwork network) {
        if (publicKey == null) {
            throw new AddressException("Public key cannot be null");
        }
        // 压缩公钥
        byte[] compressed = compressPublicKey(publicKey);
        // HASH160
        byte[] witnessProgram = hash160(compressed);
        return new Bech32Address(witnessProgram, network, BtcAddressType.P2WPKH, 0);
    }

    /**
     * 从脚本创建 P2WSH 地址
     */
    public static Bech32Address p2wshFromScript(byte[] script, BtcNetwork network) {
        if (script == null) {
            throw new AddressException("Script cannot be null");
        }
        // SHA256 (not HASH160 for P2WSH)
        byte[] witnessProgram = io.github.superedison.web3.crypto.hash.Sha256.hash(script);
        return new Bech32Address(witnessProgram, network, BtcAddressType.P2WSH, 0);
    }

    /**
     * 从 witness program 创建地址
     */
    public static Bech32Address fromWitnessProgram(int witnessVersion, byte[] witnessProgram, BtcNetwork network) {
        if (witnessVersion != 0) {
            throw new AddressException("Bech32Address only supports witness version 0, use TaprootAddress for v1");
        }
        if (witnessProgram == null) {
            throw new AddressException("Witness program cannot be null");
        }

        BtcAddressType type;
        if (witnessProgram.length == P2WPKH_PROGRAM_LENGTH) {
            type = BtcAddressType.P2WPKH;
        } else if (witnessProgram.length == P2WSH_PROGRAM_LENGTH) {
            type = BtcAddressType.P2WSH;
        } else {
            throw new AddressException("Invalid witness program length: " + witnessProgram.length);
        }

        return new Bech32Address(witnessProgram, network, type, witnessVersion);
    }

    /**
     * 从 Bech32 编码的地址字符串解析
     */
    public static Bech32Address fromBech32(String address) {
        if (address == null || address.isEmpty()) {
            throw AddressException.invalidFormat(address);
        }

        try {
            // 确定网络
            BtcNetwork network;
            String hrp;
            if (address.toLowerCase().startsWith("bc1")) {
                network = BtcNetwork.MAINNET;
                hrp = "bc";
            } else if (address.toLowerCase().startsWith("tb1")) {
                network = BtcNetwork.TESTNET;
                hrp = "tb";
            } else if (address.toLowerCase().startsWith("bcrt1")) {
                network = BtcNetwork.REGTEST;
                hrp = "bcrt";
            } else {
                throw AddressException.invalidFormat(address);
            }

            Bech32.DecodedSegWitAddress decoded = Bech32.decodeSegWitAddress(hrp, address);

            if (decoded.witnessVersion() != 0) {
                throw new AddressException("Expected witness version 0, got " + decoded.witnessVersion());
            }

            return fromWitnessProgram(decoded.witnessVersion(), decoded.witnessProgram(), network);
        } catch (IllegalArgumentException e) {
            throw new AddressException("Invalid Bech32 address: " + address, e);
        }
    }

    /**
     * 验证 Native SegWit 地址格式
     */
    public static boolean isValid(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        // 检查前缀 (witness version 0)
        String lower = address.toLowerCase();
        if (!lower.startsWith("bc1q") && !lower.startsWith("tb1q") && !lower.startsWith("bcrt1q")) {
            return false;
        }
        try {
            fromBech32(address);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 获取 witness version
     */
    public int getWitnessVersion() {
        return witnessVersion;
    }

    /**
     * 获取 witness program
     */
    public byte[] getWitnessProgram() {
        return getHash();
    }

    @Override
    public String toBase58() {
        // Bech32 地址不使用 Base58，返回 Bech32 编码
        return toBech32();
    }

    /**
     * 获取 Bech32 编码的地址
     */
    public String toBech32() {
        return Bech32.encodeSegWitAddress(network.getBech32Hrp(), witnessVersion, hash);
    }

    /**
     * 获取脚本公钥（ScriptPubKey）
     * OP_0 <witness program length> <witness program>
     */
    public byte[] getScriptPubKey() {
        byte[] script = new byte[2 + hash.length];
        script[0] = 0x00; // OP_0 (witness version 0)
        script[1] = (byte) hash.length; // Push witness program
        System.arraycopy(hash, 0, script, 2, hash.length);
        return script;
    }

    @Override
    public String toString() {
        return toBech32();
    }
}
