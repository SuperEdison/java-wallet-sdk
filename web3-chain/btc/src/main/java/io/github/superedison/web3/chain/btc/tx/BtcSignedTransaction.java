package io.github.superedison.web3.chain.btc.tx;

import io.github.superedison.web3.core.tx.SignedTransaction;

import java.util.Arrays;

/**
 * Bitcoin 已签名交易
 */
public final class BtcSignedTransaction implements SignedTransaction<BtcRawTransaction> {

    private final BtcRawTransaction rawTransaction;
    private final String from;
    private final byte[] rawBytes;
    private final byte[] txHash;
    private final byte[] wtxid;

    public BtcSignedTransaction(
            BtcRawTransaction rawTransaction,
            String from,
            byte[] rawBytes,
            byte[] txHash,
            byte[] wtxid
    ) {
        this.rawTransaction = rawTransaction;
        this.from = from;
        this.rawBytes = Arrays.copyOf(rawBytes, rawBytes.length);
        this.txHash = Arrays.copyOf(txHash, txHash.length);
        this.wtxid = wtxid != null ? Arrays.copyOf(wtxid, wtxid.length) : txHash;
    }

    @Override
    public BtcRawTransaction rawTransaction() {
        return rawTransaction;
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
     * 获取 witness transaction ID (for SegWit)
     */
    public byte[] getWtxid() {
        return Arrays.copyOf(wtxid, wtxid.length);
    }

    /**
     * 获取十六进制格式的交易哈希
     */
    public String txHashHex() {
        return bytesToHex(reverseBytes(txHash));
    }

    /**
     * 获取十六进制格式的原始交易数据
     */
    public String encodeHex() {
        return bytesToHex(rawBytes);
    }

    /**
     * 获取虚拟大小（vsize）用于费用计算
     */
    public int getVsize() {
        if (!rawTransaction.isSegwit()) {
            return rawBytes.length;
        }
        // vsize = (weight + 3) / 4
        // weight = base_size * 3 + total_size
        // 简化计算：假设 witness 数据大约占 total_size 的一定比例
        return (rawBytes.length + 3) / 4;
    }

    public boolean isValid() {
        return rawTransaction != null && from != null && rawBytes.length > 0 && txHash.length == 32;
    }

    private static byte[] reverseBytes(byte[] bytes) {
        byte[] reversed = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            reversed[i] = bytes[bytes.length - 1 - i];
        }
        return reversed;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
