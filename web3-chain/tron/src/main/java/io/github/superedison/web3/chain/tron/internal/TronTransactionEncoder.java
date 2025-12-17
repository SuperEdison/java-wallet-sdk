package io.github.superedison.web3.chain.tron.internal;

import io.github.superedison.web3.chain.tron.protobuf.TronProtobuf;
import io.github.superedison.web3.chain.tron.tx.TronRawTransaction;
import io.github.superedison.web3.chain.tron.tx.TronTransactionType;
import io.github.superedison.web3.chain.spi.TransactionEncoder;

/**
 * TRON 交易编码（Protobuf）。
 */
public final class TronTransactionEncoder implements TransactionEncoder<TronRawTransaction> {

    @Override
    public byte[] encode(TronRawTransaction tx) {
        // 1. 合约内容
        byte[] contractContent;
        String typeUrl;

        if (tx.getType() == TronTransactionType.TRANSFER_CONTRACT) {
            contractContent = TronProtobuf.encodeTransferContract(
                    tx.getOwnerAddress(),
                    tx.getToAddress(),
                    tx.getAmount()
            );
            typeUrl = TronProtobuf.getTransferContractTypeUrl();
        } else {
            contractContent = TronProtobuf.encodeTriggerSmartContract(
                    tx.getOwnerAddress(),
                    tx.getToAddress(),
                    tx.getAmount(),
                    tx.getData()
            );
            typeUrl = TronProtobuf.getTriggerSmartContractTypeUrl();
        }

        byte[] anyParameter = TronProtobuf.encodeAny(typeUrl, contractContent);
        byte[] contract = TronProtobuf.encodeContract(tx.getType().getValue(), anyParameter);

        // raw_data 编码
        return TronProtobuf.encodeRawTransaction(
                tx.getRefBlockBytes(),
                tx.getRefBlockHash(),
                tx.getExpiration(),
                tx.getTimestamp(),
                contract,
                tx.getFeeLimit()
        );
    }
}
