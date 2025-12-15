package io.github.superedison.web3.core.exception;

/**
 * 链相关异常
 */
public class ChainException extends Web3Exception {

    public ChainException(String message) {
        super(message);
    }

    public ChainException(String message, Throwable cause) {
        super(message, cause);
    }

    public ChainException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public ChainException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}