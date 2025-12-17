package io.github.superedison.web3.chain.btc.address;

import io.github.superedison.web3.chain.exception.AddressException;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.crypto.hash.Sha256;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Bitcoin 地址统一接口
 *
 * 支持多种地址类型：
 * - P2PKH: Legacy (以 '1' 开头)
 * - P2SH-P2WPKH: Wrapped SegWit (以 '3' 开头)
 * - P2WPKH: Native SegWit (以 'bc1q' 开头)
 * - P2WSH: Native SegWit Script (以 'bc1q' 开头，更长)
 * - P2TR: Taproot (以 'bc1p' 开头)
 */
public sealed abstract class BtcAddress implements Address
        permits P2PKHAddress, P2SHAddress, Bech32Address, TaprootAddress {

    protected final byte[] hash;
    protected final BtcNetwork network;
    protected final BtcAddressType type;

    protected BtcAddress(byte[] hash, BtcNetwork network, BtcAddressType type) {
        this.hash = Arrays.copyOf(hash, hash.length);
        this.network = network;
        this.type = type;
    }

    /**
     * 从地址字符串解析
     */
    public static BtcAddress fromString(String address) {
        return fromString(address, null);
    }

    /**
     * 从地址字符串解析，指定期望的网络
     */
    public static BtcAddress fromString(String address, BtcNetwork expectedNetwork) {
        if (address == null || address.isEmpty()) {
            throw AddressException.invalidFormat(address);
        }

        BtcAddressType type = BtcAddressType.fromAddress(address);
        if (type == null) {
            throw AddressException.invalidFormat(address);
        }

        BtcNetwork network = BtcNetwork.fromAddress(address);
        if (expectedNetwork != null && network != expectedNetwork) {
            throw new AddressException("Network mismatch: expected " + expectedNetwork + ", got " + network);
        }

        return switch (type) {
            case P2PKH -> P2PKHAddress.fromBase58(address);
            case P2SH_P2WPKH -> P2SHAddress.fromBase58(address);
            case P2WPKH, P2WSH -> Bech32Address.fromBech32(address);
            case P2TR -> TaprootAddress.fromBech32(address);
        };
    }

    /**
     * 从公钥创建 P2PKH 地址（Legacy）
     */
    public static P2PKHAddress p2pkhFromPublicKey(byte[] publicKey, BtcNetwork network) {
        return P2PKHAddress.fromPublicKey(publicKey, network);
    }

    /**
     * 从公钥创建 P2SH-P2WPKH 地址（Wrapped SegWit）
     */
    public static P2SHAddress p2shP2wpkhFromPublicKey(byte[] publicKey, BtcNetwork network) {
        return P2SHAddress.fromPublicKeyP2WPKH(publicKey, network);
    }

    /**
     * 从公钥创建 P2WPKH 地址（Native SegWit）
     */
    public static Bech32Address p2wpkhFromPublicKey(byte[] publicKey, BtcNetwork network) {
        return Bech32Address.p2wpkhFromPublicKey(publicKey, network);
    }

    /**
     * 从公钥创建 P2TR 地址（Taproot）
     */
    public static TaprootAddress p2trFromPublicKey(byte[] publicKey, BtcNetwork network) {
        return TaprootAddress.fromPublicKey(publicKey, network);
    }

    /**
     * 验证地址格式
     */
    public static boolean isValid(String address) {
        try {
            fromString(address);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 获取地址类型
     */
    public BtcAddressType getType() {
        return type;
    }

    /**
     * 获取网络
     */
    public BtcNetwork getNetwork() {
        return network;
    }

    /**
     * 获取哈希（RIPEMD160 或 SHA256 哈希，取决于地址类型）
     */
    public byte[] getHash() {
        return Arrays.copyOf(hash, hash.length);
    }

    @Override
    public byte[] toBytes() {
        return getHash();
    }

    @Override
    public boolean isValid() {
        return true;
    }

    /**
     * 计算 HASH160 (RIPEMD160(SHA256(data)))
     */
    protected static byte[] hash160(byte[] data) {
        byte[] sha256 = Sha256.hash(data);
        return ripemd160(sha256);
    }

    /**
     * 计算 RIPEMD160
     */
    protected static byte[] ripemd160(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("RIPEMD160");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            // 使用 BouncyCastle
            org.bouncycastle.crypto.digests.RIPEMD160Digest ripemd160 =
                    new org.bouncycastle.crypto.digests.RIPEMD160Digest();
            ripemd160.update(data, 0, data.length);
            byte[] result = new byte[20];
            ripemd160.doFinal(result, 0);
            return result;
        }
    }

    /**
     * 获取公钥的压缩形式
     */
    protected static byte[] compressPublicKey(byte[] publicKey) {
        if (publicKey.length == 33) {
            return publicKey;
        }
        if (publicKey.length != 65 || publicKey[0] != 0x04) {
            throw new IllegalArgumentException("Invalid public key format");
        }
        byte[] compressed = new byte[33];
        compressed[0] = (byte) ((publicKey[64] & 1) == 0 ? 0x02 : 0x03);
        System.arraycopy(publicKey, 1, compressed, 1, 32);
        return compressed;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof BtcAddress that)) return false;
        return type == that.type && network == that.network && Arrays.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(hash);
        result = 31 * result + network.hashCode();
        result = 31 * result + type.hashCode();
        return result;
    }
}
