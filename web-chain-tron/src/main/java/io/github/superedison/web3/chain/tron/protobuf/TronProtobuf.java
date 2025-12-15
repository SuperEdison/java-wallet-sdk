package io.github.superedison.web3.chain.tron.protobuf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * 简化的 Protobuf 编码器
 * 仅实现 TRON 交易所需的字段类型
 */
public final class TronProtobuf {

    // Protobuf 线类型
    public static final int WIRE_VARINT = 0;    // int, bool
    public static final int WIRE_64BIT = 1;     // fixed64
    public static final int WIRE_LEN = 2;       // bytes, string, 嵌套消息
    public static final int WIRE_32BIT = 5;     // fixed32

    private TronProtobuf() {}

    /**
     * 编码 varint
     */
    public static void writeVarint(ByteArrayOutputStream out, long value) {
        while ((value & ~0x7FL) != 0) {
            out.write((int) ((value & 0x7F) | 0x80));
            value >>>= 7;
        }
        out.write((int) value);
    }

    /**
     * 编码 tag (field_number << 3 | wire_type)
     */
    public static void writeTag(ByteArrayOutputStream out, int fieldNumber, int wireType) {
        writeVarint(out, (long) fieldNumber << 3 | wireType);
    }

    /**
     * 编码字节数组字段
     */
    public static void writeBytes(ByteArrayOutputStream out, int fieldNumber, byte[] value) {
        if (value == null || value.length == 0) {
            return;
        }
        writeTag(out, fieldNumber, WIRE_LEN);
        writeVarint(out, value.length);
        try {
            out.write(value);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 编码 int64 字段
     */
    public static void writeInt64(ByteArrayOutputStream out, int fieldNumber, long value) {
        if (value == 0) {
            return;
        }
        writeTag(out, fieldNumber, WIRE_VARINT);
        writeVarint(out, value);
    }

    /**
     * 编码嵌套消息
     */
    public static void writeMessage(ByteArrayOutputStream out, int fieldNumber, byte[] message) {
        if (message == null || message.length == 0) {
            return;
        }
        writeTag(out, fieldNumber, WIRE_LEN);
        writeVarint(out, message.length);
        try {
            out.write(message);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 编码 TransferContract
     * message TransferContract {
     *   bytes owner_address = 1;
     *   bytes to_address = 2;
     *   int64 amount = 3;
     * }
     */
    public static byte[] encodeTransferContract(byte[] ownerAddress, byte[] toAddress, long amount) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBytes(out, 1, ownerAddress);
        writeBytes(out, 2, toAddress);
        writeInt64(out, 3, amount);
        return out.toByteArray();
    }

    /**
     * 编码 TriggerSmartContract
     * message TriggerSmartContract {
     *   bytes owner_address = 1;
     *   bytes contract_address = 2;
     *   int64 call_value = 3;
     *   bytes data = 4;
     *   int64 call_token_value = 5;
     *   int64 token_id = 6;
     * }
     */
    public static byte[] encodeTriggerSmartContract(byte[] ownerAddress, byte[] contractAddress,
                                                     long callValue, byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBytes(out, 1, ownerAddress);
        writeBytes(out, 2, contractAddress);
        writeInt64(out, 3, callValue);
        writeBytes(out, 4, data);
        return out.toByteArray();
    }

    /**
     * 编码 Contract.parameter (google.protobuf.Any)
     * message Any {
     *   string type_url = 1;
     *   bytes value = 2;
     * }
     */
    public static byte[] encodeAny(String typeUrl, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // type_url
        byte[] typeUrlBytes = typeUrl.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        writeTag(out, 1, WIRE_LEN);
        writeVarint(out, typeUrlBytes.length);
        try {
            out.write(typeUrlBytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // value
        writeBytes(out, 2, value);
        return out.toByteArray();
    }

    /**
     * 编码 Contract
     * message Contract {
     *   ContractType type = 1;
     *   google.protobuf.Any parameter = 2;
     * }
     */
    public static byte[] encodeContract(int contractType, byte[] anyParameter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // type (enum)
        writeTag(out, 1, WIRE_VARINT);
        writeVarint(out, contractType);
        // parameter (Any)
        writeMessage(out, 2, anyParameter);
        return out.toByteArray();
    }

    /**
     * 编码 raw 交易
     * message raw {
     *   bytes ref_block_bytes = 1;
     *   int64 ref_block_num = 3;
     *   bytes ref_block_hash = 4;
     *   int64 expiration = 8;
     *   repeated Contract contract = 11;
     *   int64 timestamp = 14;
     *   int64 fee_limit = 18;
     * }
     */
    public static byte[] encodeRawTransaction(
            byte[] refBlockBytes,
            byte[] refBlockHash,
            long expiration,
            long timestamp,
            byte[] contract,
            long feeLimit
    ) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // ref_block_bytes (field 1)
        writeBytes(out, 1, refBlockBytes);

        // ref_block_hash (field 4)
        writeBytes(out, 4, refBlockHash);

        // expiration (field 8)
        writeInt64(out, 8, expiration);

        // contract (field 11) - repeated, 但这里只支持单个合约
        writeMessage(out, 11, contract);

        // timestamp (field 14)
        writeInt64(out, 14, timestamp);

        // fee_limit (field 18) - 仅智能合约交易需要
        if (feeLimit > 0) {
            writeInt64(out, 18, feeLimit);
        }

        return out.toByteArray();
    }

    /**
     * 编码已签名交易
     * message Transaction {
     *   raw raw_data = 1;
     *   repeated bytes signature = 2;
     * }
     */
    public static byte[] encodeSignedTransaction(byte[] rawTransaction, byte[] signature) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // raw_data (field 1)
        writeMessage(out, 1, rawTransaction);
        // signature (field 2) - repeated, 但这里只支持单签名
        writeBytes(out, 2, signature);
        return out.toByteArray();
    }

    /**
     * 获取 TransferContract 的 type_url
     */
    public static String getTransferContractTypeUrl() {
        return "type.googleapis.com/protocol.TransferContract";
    }

    /**
     * 获取 TriggerSmartContract 的 type_url
     */
    public static String getTriggerSmartContractTypeUrl() {
        return "type.googleapis.com/protocol.TriggerSmartContract";
    }
}
