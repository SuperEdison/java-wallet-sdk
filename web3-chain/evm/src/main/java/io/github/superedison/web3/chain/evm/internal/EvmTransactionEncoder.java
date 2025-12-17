package io.github.superedison.web3.chain.evm.internal;

import io.github.superedison.web3.chain.evm.rlp.RlpEncoder;
import io.github.superedison.web3.chain.evm.tx.EvmRawTransaction;
import io.github.superedison.web3.chain.spi.TransactionEncoder;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * EVM 交易编码（RLP）。
 */
public final class EvmTransactionEncoder implements TransactionEncoder<EvmRawTransaction> {

    @Override
    public byte[] encode(EvmRawTransaction tx) {
        return encodeForSigning(tx);
    }

    /**
     * EIP-155 签名编码：RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
     */
    public byte[] encodeForSigning(EvmRawTransaction tx) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(RlpEncoder.encodeBigInteger(tx.getNonce()));
        fields.add(RlpEncoder.encodeBigInteger(tx.getGasPrice()));
        fields.add(RlpEncoder.encodeBigInteger(tx.getGasLimit()));
        fields.add(RlpEncoder.encodeAddress(tx.getTo()));
        fields.add(RlpEncoder.encodeBigInteger(tx.getValue()));
        fields.add(RlpEncoder.encodeBytes(tx.getData()));

        if (tx.getChainId() > 0) {
            fields.add(RlpEncoder.encodeLong(tx.getChainId()));
            fields.add(RlpEncoder.encodeBigInteger(BigInteger.ZERO));
            fields.add(RlpEncoder.encodeBigInteger(BigInteger.ZERO));
        }

        return RlpEncoder.encodeList(fields);
    }

    /**
     * 签名后编码：RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
     */
    public byte[] encodeSigned(EvmRawTransaction tx, EvmSignature signature) {
        List<byte[]> fields = new ArrayList<>();
        fields.add(RlpEncoder.encodeBigInteger(tx.getNonce()));
        fields.add(RlpEncoder.encodeBigInteger(tx.getGasPrice()));
        fields.add(RlpEncoder.encodeBigInteger(tx.getGasLimit()));
        fields.add(RlpEncoder.encodeAddress(tx.getTo()));
        fields.add(RlpEncoder.encodeBigInteger(tx.getValue()));
        fields.add(RlpEncoder.encodeBytes(tx.getData()));

        fields.add(RlpEncoder.encodeLong(signature.getV()));
        fields.add(RlpEncoder.encodeBigInteger(signature.getRBigInt()));
        fields.add(RlpEncoder.encodeBigInteger(signature.getSBigInt()));

        return RlpEncoder.encodeList(fields);
    }
}
