package io.github.superedison.web3.chain.solana.internal;

import io.github.superedison.web3.chain.solana.address.SolanaAddress;
import io.github.superedison.web3.chain.solana.tx.SolanaRawTransaction;
import io.github.superedison.web3.chain.solana.tx.SolanaSignedTransaction;
import io.github.superedison.web3.chain.spi.TransactionSigner;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.SigningKey;

/**
 * Solana 交易签名器
 */
public final class SolanaTransactionSigner implements TransactionSigner<SolanaRawTransaction, SolanaSignedTransaction> {

    private final SolanaTransactionEncoder encoder;

    public SolanaTransactionSigner(SolanaTransactionEncoder encoder) {
        this.encoder = encoder;
    }

    @Override
    public SolanaSignedTransaction sign(SolanaRawTransaction tx, SigningKey key) {
        if (key.getScheme() != SignatureScheme.ED25519) {
            throw new IllegalArgumentException("Solana requires Ed25519 signing key");
        }

        // 编码消息
        byte[] message = encoder.encodeMessage(tx);

        // 0.1.0 仅支持单 signer。message[0] 即 numRequiredSignatures（消息头第一字节）；
        // 若 > 1，直接签出来会因签名数与消息头不一致而被节点拒绝。多 signer API 留到 0.2.0。
        int numRequiredSignatures = message[0] & 0xFF;
        if (numRequiredSignatures != 1) {
            throw new UnsupportedOperationException(
                    "Solana single-signer transactions only (got " + numRequiredSignatures
                            + " required signatures). Multi-signer support is planned for 0.2.0; "
                            + "for now, ensure the transaction has exactly one account with isSigner=true.");
        }

        // 签名（Ed25519 直接对消息签名，不需要预哈希）
        Signature sig = key.sign(message);
        byte[] signatureBytes = sig.bytes();

        if (signatureBytes.length != 64) {
            throw new IllegalArgumentException("Ed25519 signature must be 64 bytes");
        }

        // 编码已签名交易
        // Bug 3 修复：传入已编码的 message 字节而非 tx，避免双重编码
        byte[] signedBytes = encoder.encodeSigned(message, new byte[][]{signatureBytes});

        // 获取发送者地址（公钥）
        byte[] publicKey = key.getPublicKey();
        String from = SolanaAddress.fromPublicKey(publicKey).toBase58();

        // Solana 的交易哈希就是签名本身
        return new SolanaSignedTransaction(tx, signatureBytes, from, signedBytes, signatureBytes);
    }
}
