package io.github.superedison.web3.chain.solana.tx;

import io.github.superedison.web3.core.tx.SignedTransaction;

import java.util.Arrays;

/**
 * Solana 已签名交易
 */
public final class SolanaSignedTransaction implements SignedTransaction<SolanaRawTransaction> {

    private final SolanaRawTransaction rawTransaction;
    private final byte[] signature;
    private final String from;
    private final byte[] rawBytes;
    private final byte[] txHash;

    public SolanaSignedTransaction(
            SolanaRawTransaction rawTransaction,
            byte[] signature,
            String from,
            byte[] rawBytes,
            byte[] txHash
    ) {
        this.rawTransaction = rawTransaction;
        this.signature = Arrays.copyOf(signature, signature.length);
        this.from = from;
        this.rawBytes = Arrays.copyOf(rawBytes, rawBytes.length);
        this.txHash = Arrays.copyOf(txHash, txHash.length);
    }

    @Override
    public SolanaRawTransaction rawTransaction() {
        return rawTransaction;
    }

    /**
     * 获取签名（64 字节 Ed25519 签名）
     */
    public byte[] signature() {
        return Arrays.copyOf(signature, signature.length);
    }

    @Override
    public byte[] rawBytes() {
        return Arrays.copyOf(rawBytes, rawBytes.length);
    }

    @Override
    public byte[] txHash() {
        return Arrays.copyOf(txHash, txHash.length);
    }

    @Override
    public String from() {
        return from;
    }

    /**
     * 获取 Base58 编码的签名
     */
    public String signatureBase58() {
        return io.github.superedison.web3.chain.solana.address.Base58.encode(signature);
    }

    /**
     * 获取 Base58 编码的交易哈希
     */
    public String txHashBase58() {
        return io.github.superedison.web3.chain.solana.address.Base58.encode(txHash);
    }

    /**
     * 获取 Base64 编码的交易数据（用于 RPC 提交）
     */
    public String encodeBase64() {
        return java.util.Base64.getEncoder().encodeToString(rawBytes);
    }

    public boolean isValid() {
        return rawTransaction != null && signature.length == 64 && from != null &&
               rawBytes.length > 0 && txHash.length == 64;
    }
}