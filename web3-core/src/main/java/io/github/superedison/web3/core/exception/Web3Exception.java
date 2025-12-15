package io.github.superedison.web3.core.exception;

/**
 * Web3 SDK 基础异常类
 * 所有 Web3 相关异常的父类
 */
public class Web3Exception extends RuntimeException {

    private final ErrorCode errorCode;

    public Web3Exception(String message) {
        super(message);
        this.errorCode = ErrorCode.UNKNOWN_ERROR;
    }

    public Web3Exception(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = ErrorCode.UNKNOWN_ERROR;
    }

    public Web3Exception(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public Web3Exception(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}