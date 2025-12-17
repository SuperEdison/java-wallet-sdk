package io.github.superedison.web3.chain.btc.address;

import io.github.superedison.web3.chain.exception.AddressException;

/**
 * Bitcoin P2SH 地址（Pay to Script Hash）
 *
 * 主要用于 Wrapped SegWit (P2SH-P2WPKH)
 * 主网地址以 '3' 开头
 * 测试网地址以 '2' 开头
 *
 * BIP-49 路径: m/49'/0'/0'/0/0
 */
public final class P2SHAddress extends BtcAddress {

    private static final int HASH_LENGTH = 20;

    private P2SHAddress(byte[] hash, BtcNetwork network) {
        super(hash, network, BtcAddressType.P2SH_P2WPKH);
    }

    /**
     * 从公钥创建 P2SH-P2WPKH 地址（Wrapped SegWit）
     *
     * 步骤：
     * 1. 压缩公钥
     * 2. 计算 HASH160(公钥) = witnessProgram
     * 3. 创建 redeemScript: OP_0 <20 bytes witnessProgram>
     * 4. 计算 HASH160(redeemScript)
     */
    public static P2SHAddress fromPublicKeyP2WPKH(byte[] publicKey, BtcNetwork network) {
        if (publicKey == null) {
            throw new AddressException("Public key cannot be null");
        }
        // 压缩公钥
        byte[] compressed = compressPublicKey(publicKey);
        // 计算公钥哈希 (witness program)
        byte[] pubKeyHash = hash160(compressed);
        // 创建 redeem script: OP_0 <20 bytes>
        byte[] redeemScript = new byte[22];
        redeemScript[0] = 0x00; // OP_0 (witness version 0)
        redeemScript[1] = 0x14; // Push 20 bytes
        System.arraycopy(pubKeyHash, 0, redeemScript, 2, 20);
        // 计算 script hash
        byte[] scriptHash = hash160(redeemScript);
        return new P2SHAddress(scriptHash, network);
    }

    /**
     * 从脚本哈希创建地址
     */
    public static P2SHAddress fromScriptHash(byte[] scriptHash, BtcNetwork network) {
        if (scriptHash == null || scriptHash.length != HASH_LENGTH) {
            throw new AddressException("P2SH script hash must be 20 bytes");
        }
        return new P2SHAddress(scriptHash, network);
    }

    /**
     * 从 Base58Check 编码的地址字符串解析
     */
    public static P2SHAddress fromBase58(String address) {
        if (address == null || address.isEmpty()) {
            throw AddressException.invalidFormat(address);
        }

        try {
            Base58Check.DecodedAddress decoded = Base58Check.decodeChecked(address);

            BtcNetwork network;
            if (decoded.version() == BtcNetwork.MAINNET.getP2shVersion()) {
                network = BtcNetwork.MAINNET;
            } else if (decoded.version() == BtcNetwork.TESTNET.getP2shVersion()) {
                network = BtcNetwork.TESTNET;
            } else {
                throw new AddressException("Invalid P2SH version: " + decoded.version());
            }

            if (decoded.hash().length != HASH_LENGTH) {
                throw new AddressException("Invalid P2SH hash length: " + decoded.hash().length);
            }

            return new P2SHAddress(decoded.hash(), network);
        } catch (IllegalArgumentException e) {
            throw new AddressException("Invalid P2SH address: " + address, e);
        }
    }

    /**
     * 验证 P2SH 地址格式
     */
    public static boolean isValid(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        // 检查前缀
        char firstChar = address.charAt(0);
        if (firstChar != '3' && firstChar != '2') {
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
        byte version = network.getP2shVersion();
        return Base58Check.encodeChecked(version, hash);
    }

    /**
     * 获取脚本公钥（ScriptPubKey）
     * OP_HASH160 <20 bytes> OP_EQUAL
     */
    public byte[] getScriptPubKey() {
        byte[] script = new byte[23];
        script[0] = (byte) 0xa9; // OP_HASH160
        script[1] = 0x14; // Push 20 bytes
        System.arraycopy(hash, 0, script, 2, 20);
        script[22] = (byte) 0x87; // OP_EQUAL
        return script;
    }

    @Override
    public String toString() {
        return toBase58();
    }
}
