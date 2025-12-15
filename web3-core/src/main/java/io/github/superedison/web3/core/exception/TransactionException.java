package io.github.superedison.web3.core.exception;

/**
 * 交易相关异常
 */
public class TransactionException extends Web3Exception {

    public TransactionException(String message) {
        super(message);
    }

    public TransactionException(String message, Throwable cause) {
        super(message, cause);
    }

    public TransactionException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public TransactionException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}
