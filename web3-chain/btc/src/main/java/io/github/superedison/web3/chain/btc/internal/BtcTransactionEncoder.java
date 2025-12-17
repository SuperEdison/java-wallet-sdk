package io.github.superedison.web3.chain.btc.internal;

import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction.TxInput;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction.TxOutput;
import io.github.superedison.web3.chain.spi.TransactionEncoder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Bitcoin 交易编码器
 */
public final class BtcTransactionEncoder implements TransactionEncoder<BtcRawTransaction> {

    @Override
    public byte[] encode(BtcRawTransaction tx) {
        return encodeTransaction(tx, true);
    }

    /**
     * 编码完整交易（包括 witness 数据）
     */
    public byte[] encodeTransaction(BtcRawTransaction tx, boolean includeWitness) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // Version (4 bytes, little-endian)
            writeUint32LE(baos, tx.getVersion());

            boolean hasWitness = includeWitness && tx.isSegwit();

            // SegWit marker and flag
            if (hasWitness) {
                baos.write(0x00); // marker
                baos.write(0x01); // flag
            }

            // Input count (varint)
            writeVarInt(baos, tx.getInputs().size());

            // Inputs
            for (TxInput input : tx.getInputs()) {
                // Previous transaction hash (32 bytes, reversed)
                baos.write(input.prevTxHash());

                // Previous output index (4 bytes, little-endian)
                writeUint32LE(baos, input.prevOutputIndex());

                // Script length and script
                byte[] scriptSig = input.scriptSig();
                writeVarInt(baos, scriptSig.length);
                baos.write(scriptSig);

                // Sequence (4 bytes, little-endian)
                writeUint32LE(baos, (int) input.sequence());
            }

            // Output count (varint)
            writeVarInt(baos, tx.getOutputs().size());

            // Outputs
            for (TxOutput output : tx.getOutputs()) {
                // Value (8 bytes, little-endian)
                writeUint64LE(baos, output.value());

                // Script length and script
                byte[] scriptPubKey = output.scriptPubKey();
                writeVarInt(baos, scriptPubKey.length);
                baos.write(scriptPubKey);
            }

            // Witness data (only if SegWit)
            if (hasWitness) {
                for (TxInput input : tx.getInputs()) {
                    byte[][] witness = input.witness();
                    if (witness != null && witness.length > 0) {
                        writeVarInt(baos, witness.length);
                        for (byte[] item : witness) {
                            writeVarInt(baos, item.length);
                            baos.write(item);
                        }
                    } else {
                        writeVarInt(baos, 0);
                    }
                }
            }

            // Lock time (4 bytes, little-endian)
            writeUint32LE(baos, (int) tx.getLockTime());

            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode Bitcoin transaction", e);
        }
    }

    /**
     * 编码用于签名的交易（不包括 witness）
     */
    public byte[] encodeForSigning(BtcRawTransaction tx) {
        return encodeTransaction(tx, false);
    }

    /**
     * 编码 BIP-143 签名哈希前像（用于 SegWit 签名）
     */
    public byte[] encodeBip143Preimage(
            BtcRawTransaction tx,
            int inputIndex,
            byte[] scriptCode,
            long amount,
            int hashType
    ) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // 1. Version (4 bytes)
            writeUint32LE(baos, tx.getVersion());

            // 2. hashPrevouts (32 bytes)
            baos.write(computeHashPrevouts(tx));

            // 3. hashSequence (32 bytes)
            baos.write(computeHashSequence(tx));

            // 4. Outpoint (36 bytes)
            TxInput input = tx.getInputs().get(inputIndex);
            baos.write(input.prevTxHash());
            writeUint32LE(baos, input.prevOutputIndex());

            // 5. scriptCode (varint + script)
            writeVarInt(baos, scriptCode.length);
            baos.write(scriptCode);

            // 6. Value (8 bytes)
            writeUint64LE(baos, amount);

            // 7. Sequence (4 bytes)
            writeUint32LE(baos, (int) input.sequence());

            // 8. hashOutputs (32 bytes)
            baos.write(computeHashOutputs(tx));

            // 9. Locktime (4 bytes)
            writeUint32LE(baos, (int) tx.getLockTime());

            // 10. Hash type (4 bytes)
            writeUint32LE(baos, hashType);

            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode BIP-143 preimage", e);
        }
    }

    /**
     * 计算 hashPrevouts (所有输入 outpoint 的双哈希)
     */
    private byte[] computeHashPrevouts(BtcRawTransaction tx) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (TxInput input : tx.getInputs()) {
            baos.write(input.prevTxHash());
            writeUint32LE(baos, input.prevOutputIndex());
        }
        return io.github.superedison.web3.crypto.hash.Sha256.doubleHash(baos.toByteArray());
    }

    /**
     * 计算 hashSequence (所有输入 sequence 的双哈希)
     */
    private byte[] computeHashSequence(BtcRawTransaction tx) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (TxInput input : tx.getInputs()) {
            writeUint32LE(baos, (int) input.sequence());
        }
        return io.github.superedison.web3.crypto.hash.Sha256.doubleHash(baos.toByteArray());
    }

    /**
     * 计算 hashOutputs (所有输出的双哈希)
     */
    private byte[] computeHashOutputs(BtcRawTransaction tx) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (TxOutput output : tx.getOutputs()) {
            writeUint64LE(baos, output.value());
            writeVarInt(baos, output.scriptPubKey().length);
            baos.write(output.scriptPubKey());
        }
        return io.github.superedison.web3.crypto.hash.Sha256.doubleHash(baos.toByteArray());
    }

    private void writeUint32LE(ByteArrayOutputStream baos, int value) {
        baos.write(value & 0xff);
        baos.write((value >> 8) & 0xff);
        baos.write((value >> 16) & 0xff);
        baos.write((value >> 24) & 0xff);
    }

    private void writeUint64LE(ByteArrayOutputStream baos, long value) {
        for (int i = 0; i < 8; i++) {
            baos.write((int) ((value >> (i * 8)) & 0xff));
        }
    }

    private void writeVarInt(ByteArrayOutputStream baos, long value) {
        if (value < 0xfd) {
            baos.write((int) value);
        } else if (value <= 0xffff) {
            baos.write(0xfd);
            baos.write((int) (value & 0xff));
            baos.write((int) ((value >> 8) & 0xff));
        } else if (value <= 0xffffffffL) {
            baos.write(0xfe);
            writeUint32LE(baos, (int) value);
        } else {
            baos.write(0xff);
            writeUint64LE(baos, value);
        }
    }
}
