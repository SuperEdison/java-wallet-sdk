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
     */
    public record TxInput(
            byte[] prevTxHash,
            int prevOutputIndex,
            byte[] scriptSig,
            long sequence,
            byte[][] witness
    ) {
        public TxInput {
            prevTxHash = Arrays.copyOf(prevTxHash, prevTxHash.length);
            scriptSig = scriptSig != null ? Arrays.copyOf(scriptSig, scriptSig.length) : new byte[0];
            if (witness != null) {
                byte[][] witnessCopy = new byte[witness.length][];
                for (int i = 0; i < witness.length; i++) {
                    witnessCopy[i] = Arrays.copyOf(witness[i], witness[i].length);
                }
                witness = witnessCopy;
            }
        }

        public byte[] prevTxHash() {
            return Arrays.copyOf(prevTxHash, prevTxHash.length);
        }

        public byte[] scriptSig() {
            return Arrays.copyOf(scriptSig, scriptSig.length);
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
            return addInput(prevTxHash, prevOutputIndex, new byte[0], 0xffffffffL, null);
        }

        public Builder addInput(byte[] prevTxHash, int prevOutputIndex, byte[] scriptSig, long sequence, byte[][] witness) {
            inputs.add(new TxInput(prevTxHash, prevOutputIndex, scriptSig, sequence, witness));
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
