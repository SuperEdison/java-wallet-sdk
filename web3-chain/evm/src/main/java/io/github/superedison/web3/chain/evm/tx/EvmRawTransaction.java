package io.github.superedison.web3.chain.evm.tx;

import io.github.superedison.web3.core.tx.RawTransaction;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * EVM Legacy 交易（EIP-155）。
 * 仅承载数据，不负责编码/哈希/签名。
 */
public final class EvmRawTransaction implements RawTransaction {

    private final BigInteger nonce;
    private final BigInteger gasPrice;
    private final BigInteger gasLimit;
    private final byte[] to;          // null 表示合约创建
    private final BigInteger value;
    private final byte[] data;
    private final long chainId;

    private EvmRawTransaction(Builder builder) {
        this.nonce = builder.nonce;
        this.gasPrice = builder.gasPrice;
        this.gasLimit = builder.gasLimit;
        this.to = builder.to;
        this.value = builder.value;
        this.data = builder.data;
        this.chainId = builder.chainId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public EvmTransactionType getType() {
        return EvmTransactionType.LEGACY;
    }

    // Getters
    public BigInteger getNonce() { return nonce; }
    public BigInteger getGasPrice() { return gasPrice; }
    public BigInteger getGasLimit() { return gasLimit; }
    public byte[] getTo() { return to != null ? Arrays.copyOf(to, to.length) : null; }
    public BigInteger getValue() { return value; }
    public byte[] getData() { return data != null ? Arrays.copyOf(data, data.length) : new byte[0]; }
    public long getChainId() { return chainId; }
    public boolean isContractCreation() { return to == null || to.length == 0; }

    public static class Builder {
        private BigInteger nonce = BigInteger.ZERO;
        private BigInteger gasPrice = BigInteger.ZERO;
        private BigInteger gasLimit = BigInteger.valueOf(21000);
        private byte[] to;
        private BigInteger value = BigInteger.ZERO;
        private byte[] data;
        private long chainId = 1;

        public Builder nonce(BigInteger nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder nonce(long nonce) {
            this.nonce = BigInteger.valueOf(nonce);
            return this;
        }

        public Builder gasPrice(BigInteger gasPrice) {
            this.gasPrice = gasPrice;
            return this;
        }

        public Builder gasLimit(BigInteger gasLimit) {
            this.gasLimit = gasLimit;
            return this;
        }

        public Builder gasLimit(long gasLimit) {
            this.gasLimit = BigInteger.valueOf(gasLimit);
            return this;
        }

        public Builder to(byte[] to) {
            this.to = to;
            return this;
        }

        public Builder to(String toHex) {
            if (toHex == null || toHex.isEmpty()) {
                this.to = null;
            } else {
                String hex = toHex.startsWith("0x") ? toHex.substring(2) : toHex;
                this.to = hexToBytes(hex);
            }
            return this;
        }

        public Builder value(BigInteger value) {
            this.value = value;
            return this;
        }

        public Builder data(byte[] data) {
            this.data = data;
            return this;
        }

        public Builder data(String dataHex) {
            if (dataHex == null || dataHex.isEmpty()) {
                this.data = new byte[0];
            } else {
                String hex = dataHex.startsWith("0x") ? dataHex.substring(2) : dataHex;
                this.data = hexToBytes(hex);
            }
            return this;
        }

        public Builder chainId(long chainId) {
            this.chainId = chainId;
            return this;
        }

        public EvmRawTransaction build() {
            return new EvmRawTransaction(this);
        }

        private static byte[] hexToBytes(String hex) {
            byte[] bytes = new byte[hex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return bytes;
        }
    }
}
