package io.github.superedison.web3.chain.evm.tx;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

/**
 * EVM 交易签名器
 */
public final class EvmTransactionSigner {

    private EvmTransactionSigner() {}

    /**
     * 签名交易 (EIP-155)
     * @param transaction 原始交易
     * @param privateKey 32 字节私钥
     * @return 已签名交易
     */
    public static EvmSignedTransaction sign(EvmRawTransaction transaction, byte[] privateKey) {
        // 1. 计算交易哈希
        byte[] hash = transaction.hash();

        // 2. secp256k1 签名（使用 try-with-resources 自动销毁私钥）
        try (Secp256k1Signer signer = new Secp256k1Signer(privateKey)) {
            var result = (Secp256k1Signer.Secp256k1Signature) signer.sign(hash);

            // 3. 转换为 EIP-155 签名
            EvmSignature signature = EvmSignature
                    .fromRecoveryId(result.r(), result.s(), result.v())
                    .toEip155(transaction.getChainId());

            // 4. 获取发送者地址
            byte[] publicKey = signer.getPublicKey();
            EvmAddress from = EvmAddress.fromPublicKey(publicKey);

            return new EvmSignedTransaction(transaction, signature, from.toChecksumHex());
        }
    }
}