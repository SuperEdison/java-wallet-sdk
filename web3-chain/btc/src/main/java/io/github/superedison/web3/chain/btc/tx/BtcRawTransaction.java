package io.github.superedison.web3.chain.btc.tx;

import io.github.superedison.web3.core.tx.RawTransaction;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Bitcoin 原始交易
 *
 * 支持 Legacy 和 SegWit 交易格式
 */
public final class BtcRawTransaction implements RawTransaction {

    private final int version;
    private final List<TxInput> inputs;
    private final List<TxOutput> outputs;
    private final long lockTime;
    private final boolean segwit;

    private BtcRawTransaction(Builder builder) {
        this.version = builder.version;
        this.inputs = Collections.unmodifiableList(new ArrayList<>(builder.inputs));
        this.outputs = Collections.unmodifiableList(new ArrayList<>(builder.outputs));
        this.lockTime = builder.lockTime;
        this.segwit = builder.segwit;
    }

    public static Builder builder() {
        return new Builder();
    }

    public int getVersion() {
        return version;
    }

    public List<TxInput> getInputs() {
        return inputs;
    }

    public List<TxOutput> getOutputs() {
        return outputs;
    }

    public long getLockTime() {
        return lockTime;
    }

    public boolean isSegwit() {
        return segwit;
    }

    /**
     * 交易输入
     *
     * amount 字段存储该输入所花费的 UTXO 金额（单位：聪），BIP-143 SegWit 签名哈希必须包含此值。
     * scriptPubKey 字段存储该输入对应的 UTXO 锁定脚本，Legacy 签名哈希替换 scriptSig 时使用。
     */
    public record TxInput(
            byte[] prevTxHash,
            int prevOutputIndex,
            byte[] scriptSig,
            long sequence,
            byte[][] witness,
            long amount,
            byte[] scriptPubKey
    ) {
        public TxInput {
            prevTxHash = Arrays.copyOf(prevTxHash, prevTxHash.length);
            scriptSig = scriptSig != null ? Arrays.copyOf(scriptSig, scriptSig.length) : new byte[0];
            scriptPubKey = scriptPubKey != null ? Arrays.copyOf(scriptPubKey, scriptPubKey.length) : new byte[0];
            if (witness != null) {
                byte[][] witnessCopy = new byte[witness.length][];
                for (int i = 0; i < witness.length; i++) {
                    witnessCopy[i] = Arrays.copyOf(witness[i], witness[i].length);
                }
                witness = witnessCopy;
            }
        }

        /**
         * 向后兼容构造：不携带 amount / scriptPubKey 的输入（amount=0, scriptPubKey=空）
         */
        public TxInput(byte[] prevTxHash, int prevOutputIndex, byte[] scriptSig, long sequence, byte[][] witness) {
            this(prevTxHash, prevOutputIndex, scriptSig, sequence, witness, 0L, new byte[0]);
        }

        public byte[] prevTxHash() {
            return Arrays.copyOf(prevTxHash, prevTxHash.length);
        }

        public byte[] scriptSig() {
            return Arrays.copyOf(scriptSig, scriptSig.length);
        }

        public byte[] scriptPubKey() {
            return Arrays.copyOf(scriptPubKey, scriptPubKey.length);
        }

        public byte[][] witness() {
            if (witness == null) return null;
            byte[][] copy = new byte[witness.length][];
            for (int i = 0; i < witness.length; i++) {
                copy[i] = Arrays.copyOf(witness[i], witness[i].length);
            }
            return copy;
        }

        /**
         * 获取 outpoint (用于签名哈希)
         */
        public byte[] getOutpoint() {
            byte[] outpoint = new byte[36];
            System.arraycopy(prevTxHash, 0, outpoint, 0, 32);
            writeUint32LE(outpoint, 32, prevOutputIndex);
            return outpoint;
        }

        private static void writeUint32LE(byte[] data, int offset, int value) {
            data[offset] = (byte) (value & 0xff);
            data[offset + 1] = (byte) ((value >> 8) & 0xff);
            data[offset + 2] = (byte) ((value >> 16) & 0xff);
            data[offset + 3] = (byte) ((value >> 24) & 0xff);
        }
    }

    /**
     * 交易输出
     */
    public record TxOutput(
            long value,
            byte[] scriptPubKey
    ) {
        public TxOutput {
            scriptPubKey = Arrays.copyOf(scriptPubKey, scriptPubKey.length);
        }

        public byte[] scriptPubKey() {
            return Arrays.copyOf(scriptPubKey, scriptPubKey.length);
        }
    }

    public static class Builder {
        private int version = 2;
        private final List<TxInput> inputs = new ArrayList<>();
        private final List<TxOutput> outputs = new ArrayList<>();
        private long lockTime = 0;
        private boolean segwit = false;

        public Builder version(int version) {
            this.version = version;
            return this;
        }

        public Builder addInput(byte[] prevTxHash, int prevOutputIndex) {
            return addInput(prevTxHash, prevOutputIndex, new byte[0], 0xffffffffL, null, 0L, new byte[0]);
        }

        /**
         * 添加 UTXO 输入，携带金额和锁定脚本（用于正确生成签名哈希）。
         *
         * @param amount      该 UTXO 的金额（聪），BIP-143 SegWit 签名时必须提供
         * @param scriptPubKey 该 UTXO 的锁定脚本，Legacy 签名时用于替换 scriptSig
         */
        public Builder addInput(byte[] prevTxHash, int prevOutputIndex,
                                long amount, byte[] scriptPubKey) {
            return addInput(prevTxHash, prevOutputIndex, new byte[0], 0xffffffffL, null, amount, scriptPubKey);
        }

        public Builder addInput(byte[] prevTxHash, int prevOutputIndex, byte[] scriptSig, long sequence, byte[][] witness) {
            return addInput(prevTxHash, prevOutputIndex, scriptSig, sequence, witness, 0L, new byte[0]);
        }

        public Builder addInput(byte[] prevTxHash, int prevOutputIndex, byte[] scriptSig, long sequence,
                                byte[][] witness, long amount, byte[] scriptPubKey) {
            inputs.add(new TxInput(prevTxHash, prevOutputIndex, scriptSig, sequence, witness, amount,
                    scriptPubKey != null ? scriptPubKey : new byte[0]));
            if (witness != null && witness.length > 0) {
                segwit = true;
            }
            return this;
        }

        public Builder addOutput(long value, byte[] scriptPubKey) {
            outputs.add(new TxOutput(value, scriptPubKey));
            return this;
        }

        public Builder lockTime(long lockTime) {
            this.lockTime = lockTime;
            return this;
        }

        public Builder segwit(boolean segwit) {
            this.segwit = segwit;
            return this;
        }

        public BtcRawTransaction build() {
            if (inputs.isEmpty()) {
                throw new IllegalStateException("Transaction must have at least one input");
            }
            if (outputs.isEmpty()) {
                throw new IllegalStateException("Transaction must have at least one output");
            }
            return new BtcRawTransaction(this);
        }
    }
}
