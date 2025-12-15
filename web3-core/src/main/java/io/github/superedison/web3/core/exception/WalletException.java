package io.github.superedison.web3.core.exception;

/**
 * 钱包相关异常
 */
public class WalletException extends Web3Exception {

    public WalletException(String message) {
        super(message);
    }

    public WalletException(String message, Throwable cause) {
        super(message, cause);
    }

    public WalletException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }

    public WalletException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }
}