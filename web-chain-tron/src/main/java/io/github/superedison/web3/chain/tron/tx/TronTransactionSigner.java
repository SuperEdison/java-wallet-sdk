package io.github.superedison.web3.chain.tron.tx;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.chain.tron.internal.TronSignature;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.util.SecureBytes;

/**
 * TRON 交易签名器
 */
public final class TronTransactionSigner {

    private TronTransactionSigner() {}

    /**
     * 签名交易
     * @param transaction 原始交易
     * @param privateKey 32 字节私钥
     * @return 已签名交易
     */
    public static TronSignedTransaction sign(TronRawTransaction transaction, byte[] privateKey) {
        if (transaction == null) {
            throw new IllegalArgumentException("Transaction cannot be null");
        }
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }

        byte[] pkCopy = SecureBytes.copy(privateKey);
        try (Secp256k1Signer signer = new Secp256k1Signer(pkCopy)) {
            // 计算交易哈希
            byte[] txHash = transaction.hash();

            // 签名
            var sig = signer.sign(txHash);
            if (!(sig instanceof Secp256k1Signer.Secp256k1Signature secpSig)) {
                throw new IllegalStateException("Unexpected signature type");
            }

            // 转换为 TronSignature
            TronSignature tronSig = TronSignature.fromSecp256k1Signature(secpSig);

            // 获取发送者地址
            byte[] publicKey = signer.getPublicKey();
            TronAddress from = TronAddress.fromPublicKey(publicKey);

            return new TronSignedTransaction(transaction, tronSig, from.toBase58());
        } finally {
            SecureBytes.secureWipe(pkCopy);
        }
    }
}
