package io.github.superedison.web3.chain.tron.protobuf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * TRON Protobuf 编码工具
 * 轻量级实现，不依赖 protobuf 库
 */
public final class TronProtobuf {

    // Protobuf wire types
    private static final int WIRE_VARINT = 0;
    private static final int WIRE_LENGTH_DELIMITED = 2;

    // Type URLs
    private static final String TRANSFER_CONTRACT_TYPE_URL = "type.googleapis.com/protocol.TransferContract";
    private static final String TRIGGER_SMART_CONTRACT_TYPE_URL = "type.googleapis.com/protocol.TriggerSmartContract";

    private TronProtobuf() {}

    public static String getTransferContractTypeUrl() {
        return TRANSFER_CONTRACT_TYPE_URL;
    }

    public static String getTriggerSmartContractTypeUrl() {
        return TRIGGER_SMART_CONTRACT_TYPE_URL;
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
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // Field 1: owner_address (bytes)
            writeField(out, 1, WIRE_LENGTH_DELIMITED, ownerAddress);
            // Field 2: to_address (bytes)
            writeField(out, 2, WIRE_LENGTH_DELIMITED, toAddress);
            // Field 3: amount (int64)
            if (amount != 0) {
                writeFieldHeader(out, 3, WIRE_VARINT);
                writeVarint(out, amount);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode TransferContract", e);
        }
    }

    /**
     * 编码 TriggerSmartContract
     * message TriggerSmartContract {
     *   bytes owner_address = 1;
     *   bytes contract_address = 2;
     *   int64 call_value = 3;
     *   bytes data = 4;
     * }
     */
    public static byte[] encodeTriggerSmartContract(byte[] ownerAddress, byte[] contractAddress, long callValue, byte[] data) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // Field 1: owner_address (bytes)
            writeField(out, 1, WIRE_LENGTH_DELIMITED, ownerAddress);
            // Field 2: contract_address (bytes)
            writeField(out, 2, WIRE_LENGTH_DELIMITED, contractAddress);
            // Field 3: call_value (int64)
            if (callValue != 0) {
                writeFieldHeader(out, 3, WIRE_VARINT);
                writeVarint(out, callValue);
            }
            // Field 4: data (bytes)
            if (data != null && data.length > 0) {
                writeField(out, 4, WIRE_LENGTH_DELIMITED, data);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode TriggerSmartContract", e);
        }
    }

    /**
     * 编码 Any
     * message Any {
     *   string type_url = 1;
     *   bytes value = 2;
     * }
     */
    public static byte[] encodeAny(String typeUrl, byte[] value) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // Field 1: type_url (string)
            byte[] typeUrlBytes = typeUrl.getBytes(StandardCharsets.UTF_8);
            writeField(out, 1, WIRE_LENGTH_DELIMITED, typeUrlBytes);
            // Field 2: value (bytes)
            writeField(out, 2, WIRE_LENGTH_DELIMITED, value);
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode Any", e);
        }
    }

    /**
     * 编码 Contract
     * message Contract {
     *   ContractType type = 1;
     *   google.protobuf.Any parameter = 2;
     * }
     */
    public static byte[] encodeContract(int type, byte[] parameter) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // Field 1: type (enum/int32)
            writeFieldHeader(out, 1, WIRE_VARINT);
            writeVarint(out, type);
            // Field 2: parameter (Any)
            writeField(out, 2, WIRE_LENGTH_DELIMITED, parameter);
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode Contract", e);
        }
    }

    /**
     * 编码 raw 交易
     * message raw {
     *   bytes ref_block_bytes = 1;
     *   int64 ref_block_num = 3;
     *   bytes ref_block_hash = 4;
     *   int64 expiration = 8;
     *   repeated authority auths = 9;
     *   bytes data = 10;
     *   repeated Contract contract = 11;
     *   bytes scripts = 12;
     *   int64 timestamp = 14;
     *   int64 fee_limit = 18;
     * }
     */
    public static byte[] encodeRawTransaction(byte[] refBlockBytes, byte[] refBlockHash,
                                               long expiration, long timestamp,
                                               byte[] contract, long feeLimit) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // Field 1: ref_block_bytes
            writeField(out, 1, WIRE_LENGTH_DELIMITED, refBlockBytes);
            // Field 4: ref_block_hash
            writeField(out, 4, WIRE_LENGTH_DELIMITED, refBlockHash);
            // Field 8: expiration
            writeFieldHeader(out, 8, WIRE_VARINT);
            writeVarint(out, expiration);
            // Field 11: contract (repeated, but we only have one)
            writeField(out, 11, WIRE_LENGTH_DELIMITED, contract);
            // Field 14: timestamp
            writeFieldHeader(out, 14, WIRE_VARINT);
            writeVarint(out, timestamp);
            // Field 18: fee_limit (only if non-zero)
            if (feeLimit > 0) {
                writeFieldHeader(out, 18, WIRE_VARINT);
                writeVarint(out, feeLimit);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode raw transaction", e);
        }
    }

    /**
     * 编码已签名交易
     * message Transaction {
     *   raw raw_data = 1;
     *   repeated bytes signature = 2;
     * }
     */
    public static byte[] encodeSignedTransaction(byte[] rawData, byte[] signature) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            // Field 1: raw_data
            writeField(out, 1, WIRE_LENGTH_DELIMITED, rawData);
            // Field 2: signature (repeated, but we only have one)
            writeField(out, 2, WIRE_LENGTH_DELIMITED, signature);
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode signed transaction", e);
        }
    }

    // ========== Helper methods ==========

    private static void writeFieldHeader(ByteArrayOutputStream out, int fieldNumber, int wireType) throws IOException {
        int tag = (fieldNumber << 3) | wireType;
        writeVarint(out, tag);
    }

    private static void writeField(ByteArrayOutputStream out, int fieldNumber, int wireType, byte[] value) throws IOException {
        if (value == null || value.length == 0) {
            return;
        }
        writeFieldHeader(out, fieldNumber, wireType);
        if (wireType == WIRE_LENGTH_DELIMITED) {
            writeVarint(out, value.length);
        }
        out.write(value);
    }

    private static void writeVarint(ByteArrayOutputStream out, long value) throws IOException {
        while (true) {
            if ((value & ~0x7FL) == 0) {
                out.write((int) value);
                return;
            }
            out.write((int) ((value & 0x7F) | 0x80));
            value >>>= 7;
        }
    }
}
