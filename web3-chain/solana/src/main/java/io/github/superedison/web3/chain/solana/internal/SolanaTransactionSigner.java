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

        // 签名（Ed25519 直接对消息签名，不需要预哈希）
        Signature sig = key.sign(message);
        byte[] signatureBytes = sig.bytes();

        if (signatureBytes.length != 64) {
            throw new IllegalArgumentException("Ed25519 signature must be 64 bytes");
        }

        // 编码已签名交易
        byte[] signedBytes = encoder.encodeSigned(tx, new byte[][]{signatureBytes});

        // 获取发送者地址（公钥）
        byte[] publicKey = key.getPublicKey();
        String from = SolanaAddress.fromPublicKey(publicKey).toBase58();

        // Solana 的交易哈希就是签名本身
        return new SolanaSignedTransaction(tx, signatureBytes, from, signedBytes, signatureBytes);
    }
}
