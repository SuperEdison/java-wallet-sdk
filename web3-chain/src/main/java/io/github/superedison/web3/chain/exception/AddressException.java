package io.github.superedison.web3.chain.exception;

/**
 * 地址异常
 */
public class AddressException extends ChainException {

    public AddressException(String message) {
        super(message);
    }

    public AddressException(String message, Throwable cause) {
        super(message, cause);
    }

    public static AddressException invalidFormat(String address) {
        return new AddressException("Invalid address format: " + address);
    }

    public static AddressException invalidChecksum(String address) {
        return new AddressException("Invalid address checksum: " + address);
    }
}