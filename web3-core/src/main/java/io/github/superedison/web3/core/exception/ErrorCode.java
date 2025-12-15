package io.github.superedison.web3.core.exception;

/**
 * 错误类型枚举
 */
public enum ErrorCode {

    // 通用错误
    UNKNOWN_ERROR("Unknown error"),
    INVALID_PARAMETER("Invalid parameter"),
    NULL_POINTER("Null pointer"),
    UNSUPPORTED_OPERATION("Unsupported operation"),

    // 钱包相关错误
    WALLET_CREATION_FAILED("Wallet creation failed"),
    WALLET_NOT_FOUND("Wallet not found"),
    INVALID_MNEMONIC("Invalid mnemonic phrase"),
    INVALID_PRIVATE_KEY("Invalid private key"),
    INVALID_ADDRESS("Invalid address"),
    ADDRESS_DERIVATION_FAILED("Address derivation failed"),

    // 签名相关错误
    SIGNING_FAILED("Signing failed"),
    SIGNATURE_VERIFICATION_FAILED("Signature verification failed"),
    INVALID_SIGNATURE("Invalid signature"),
    MESSAGE_HASH_FAILED("Message hash failed"),

    // 交易相关错误
    TRANSACTION_BUILD_FAILED("Transaction build failed"),
    TRANSACTION_SIGN_FAILED("Transaction sign failed"),
    TRANSACTION_SERIALIZE_FAILED("Transaction serialization failed"),
    TRANSACTION_DESERIALIZE_FAILED("Transaction deserialization failed"),
    INVALID_TRANSACTION("Invalid transaction"),

    // 链相关错误
    CHAIN_NOT_SUPPORTED("Chain not supported"),
    CHAIN_CONFIG_ERROR("Chain configuration error"),
    CHAIN_ADAPTER_NOT_FOUND("Chain adapter not found"),
    CHAIN_CONNECTION_FAILED("Chain connection failed");

    private final String message;

    ErrorCode(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}