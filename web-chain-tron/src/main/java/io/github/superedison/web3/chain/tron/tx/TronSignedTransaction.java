package io.github.superedison.web3.chain.tron.tx;

import io.github.superedison.web3.chain.tron.internal.TronSignature;
import io.github.superedison.web3.chain.tron.protobuf.TronProtobuf;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.SignedTransaction;
import io.github.superedison.web3.crypto.hash.Sha256;

import java.util.Arrays;

/**
 * TRON 已签名交易
 */
public final class TronSignedTransaction implements SignedTransaction {

    private final TronRawTransaction rawTransaction;
    private final TronSignature signature;
    private final String from;

    public TronSignedTransaction(TronRawTransaction rawTransaction, TronSignature signature, String from) {
        this.rawTransaction = rawTransaction;
        this.signature = signature;
        this.from = from;
    }

    @Override
    public RawTransaction getRawTransaction() {
        return rawTransaction;
    }

    @Override
    public Signature getSignature() {
        return signature;
    }

    @Override
    public String getFrom() {
        return from;
    }

    @Override
    public byte[] getTransactionHash() {
        // TRON 交易哈希是对已签名交易的 raw_data 进行 SHA256 哈希
        return rawTransaction.hash();
    }

    /**
     * 获取交易哈希的十六进制字符串
     */
    public String getTransactionHashHex() {
        return bytesToHex(getTransactionHash());
    }

    @Override
    public byte[] encode() {
        byte[] rawData = rawTransaction.encode();
        byte[] sig = signature.bytes();
        return TronProtobuf.encodeSignedTransaction(rawData, sig);
    }

    /**
     * 获取编码后的十六进制字符串
     */
    public String encodeHex() {
        return bytesToHex(encode());
    }

    @Override
    public boolean isValid() {
        return rawTransaction != null && signature != null && from != null;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TronSignedTransaction that)) return false;
        return Arrays.equals(encode(), that.encode());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encode());
    }

    @Override
    public String toString() {
        return "TronSignedTransaction{txHash=" + getTransactionHashHex() + ", from=" + from + "}";
    }
}
