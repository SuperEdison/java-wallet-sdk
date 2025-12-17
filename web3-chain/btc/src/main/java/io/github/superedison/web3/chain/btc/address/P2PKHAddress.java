package io.github.superedison.web3.chain.btc.address;

import io.github.superedison.web3.chain.exception.AddressException;

import java.util.Arrays;

/**
 * Bitcoin P2PKH 地址（Legacy）
 *
 * 格式：HASH160(公钥) = RIPEMD160(SHA256(公钥))
 * 主网地址以 '1' 开头
 * 测试网地址以 'm' 或 'n' 开头
 *
 * BIP-44 路径: m/44'/0'/0'/0/0
 */
public final class P2PKHAddress extends BtcAddress {

    private static final int HASH_LENGTH = 20;

    private P2PKHAddress(byte[] hash, BtcNetwork network) {
        super(hash, network, BtcAddressType.P2PKH);
    }

    /**
     * 从公钥创建 P2PKH 地址
     *
     * @param publicKey 33 字节压缩公钥或 65 字节未压缩公钥
     * @param network 网络类型
     */
    public static P2PKHAddress fromPublicKey(byte[] publicKey, BtcNetwork network) {
        if (publicKey == null) {
            throw new AddressException("Public key cannot be null");
        }
        // 压缩公钥
        byte[] compressed = compressPublicKey(publicKey);
        // HASH160
        byte[] hash = hash160(compressed);
        return new P2PKHAddress(hash, network);
    }

    /**
     * 从 HASH160 创建地址
     */
    public static P2PKHAddress fromHash(byte[] hash, BtcNetwork network) {
        if (hash == null || hash.length != HASH_LENGTH) {
            throw new AddressException("P2PKH hash must be 20 bytes");
        }
        return new P2PKHAddress(hash, network);
    }

    /**
     * 从 Base58Check 编码的地址字符串解析
     */
    public static P2PKHAddress fromBase58(String address) {
        if (address == null || address.isEmpty()) {
            throw AddressException.invalidFormat(address);
        }

        try {
            Base58Check.DecodedAddress decoded = Base58Check.decodeChecked(address);

            BtcNetwork network;
            if (decoded.version() == BtcNetwork.MAINNET.getP2pkhVersion()) {
                network = BtcNetwork.MAINNET;
            } else if (decoded.version() == BtcNetwork.TESTNET.getP2pkhVersion()) {
                network = BtcNetwork.TESTNET;
            } else {
                throw new AddressException("Invalid P2PKH version: " + decoded.version());
            }

            if (decoded.hash().length != HASH_LENGTH) {
                throw new AddressException("Invalid P2PKH hash length: " + decoded.hash().length);
            }

            return new P2PKHAddress(decoded.hash(), network);
        } catch (IllegalArgumentException e) {
            throw new AddressException("Invalid P2PKH address: " + address, e);
        }
    }

    /**
     * 验证 P2PKH 地址格式
     */
    public static boolean isValid(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        // 检查前缀
        char firstChar = address.charAt(0);
        if (firstChar != '1' && firstChar != 'm' && firstChar != 'n') {
            return false;
        }
        try {
            fromBase58(address);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String toBase58() {
        byte version = network.getP2pkhVersion();
        return Base58Check.encodeChecked(version, hash);
    }

    /**
     * 获取脚本公钥（ScriptPubKey）
     * OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
     */
    public byte[] getScriptPubKey() {
        byte[] script = new byte[25];
        script[0] = 0x76; // OP_DUP
        script[1] = (byte) 0xa9; // OP_HASH160
        script[2] = 0x14; // Push 20 bytes
        System.arraycopy(hash, 0, script, 3, 20);
        script[23] = (byte) 0x88; // OP_EQUALVERIFY
        script[24] = (byte) 0xac; // OP_CHECKSIG
        return script;
    }

    @Override
    public String toString() {
        return toBase58();
    }
}
