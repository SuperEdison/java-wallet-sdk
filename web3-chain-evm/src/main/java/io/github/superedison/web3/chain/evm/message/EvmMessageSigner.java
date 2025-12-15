package io.github.superedison.web3.chain.evm.message;

import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

/**
 * EVM 消息签名器
 * 实现 EIP-191 (personal_sign)
 */
public final class EvmMessageSigner {

    private EvmMessageSigner() {}

    /**
     * 签名消息 (EIP-191 personal_sign)
     * @param message 原始消息
     * @param privateKey 32 字节私钥
     * @return 签名
     */
    public static Signature signMessage(byte[] message, byte[] privateKey) {
        byte[] hash = Eip191Prefix.hash(message);
        return signHash(hash, privateKey);
    }

    /**
     * 签名字符串消息
     */
    public static Signature signMessage(String message, byte[] privateKey) {
        byte[] hash = Eip191Prefix.hash(message);
        return signHash(hash, privateKey);
    }

    /**
     * 签名哈希（32 字节）
     */
    public static Signature signHash(byte[] hash, byte[] privateKey) {
        try (Secp256k1Signer signer = new Secp256k1Signer(privateKey)) {
            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(hash);
            return EvmSignature.fromRecoveryId(result.r(), result.s(), result.v());
        }
    }

    /**
     * 验证消息签名
     */
    public static boolean verifyMessage(byte[] message, Signature signature, byte[] publicKey) {
        byte[] hash = Eip191Prefix.hash(message);
        return verifyHash(hash, signature, publicKey);
    }

    /**
     * 验证哈希签名
     */
    public static boolean verifyHash(byte[] hash, Signature signature, byte[] publicKey) {
        if (!(signature instanceof EvmSignature evmSig)) {
            return false;
        }
        return Secp256k1Signer.verify(hash, evmSig.getR(), evmSig.getS(), publicKey);
    }
}