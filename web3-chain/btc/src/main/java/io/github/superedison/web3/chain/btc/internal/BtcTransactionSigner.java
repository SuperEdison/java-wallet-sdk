package io.github.superedison.web3.chain.btc.internal;

import io.github.superedison.web3.chain.btc.address.BtcAddress;
import io.github.superedison.web3.chain.btc.address.BtcNetwork;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction.TxInput;
import io.github.superedison.web3.chain.btc.tx.BtcSignedTransaction;
import io.github.superedison.web3.chain.spi.TransactionSigner;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Bitcoin 交易签名器
 */
public final class BtcTransactionSigner implements TransactionSigner<BtcRawTransaction, BtcSignedTransaction> {

    private static final int SIGHASH_ALL = 0x01;

    private final BtcTransactionEncoder encoder;
    private final BtcTransactionHasher hasher;
    private final BtcNetwork network;

    public BtcTransactionSigner(BtcTransactionEncoder encoder, BtcTransactionHasher hasher, BtcNetwork network) {
        this.encoder = encoder;
        this.hasher = hasher;
        this.network = network;
    }

    @Override
    public BtcSignedTransaction sign(BtcRawTransaction tx, SigningKey key) {
        if (key.getScheme() != SignatureScheme.ECDSA_SECP256K1) {
            throw new IllegalArgumentException("Bitcoin requires secp256k1 signing key");
        }

        // 获取压缩公钥
        byte[] publicKey = key.getPublicKey();
        byte[] compressedPubKey = compressPublicKey(publicKey);

        // 获取发送者地址
        String from = BtcAddress.p2wpkhFromPublicKey(compressedPubKey, network).toBase58();

        // 根据交易类型签名
        if (tx.isSegwit()) {
            return signSegwit(tx, key, compressedPubKey, from);
        } else {
            return signLegacy(tx, key, compressedPubKey, from);
        }
    }

    /**
     * SegWit 签名 (P2WPKH)
     */
    private BtcSignedTransaction signSegwit(BtcRawTransaction tx, SigningKey key, byte[] pubKey, String from) {
        try {
            // 为每个输入签名
            List<TxInput> signedInputs = new ArrayList<>();

            for (int i = 0; i < tx.getInputs().size(); i++) {
                TxInput input = tx.getInputs().get(i);

                // 创建 P2WPKH scriptCode: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
                byte[] pubKeyHash = hash160(pubKey);
                byte[] scriptCode = createP2PKHScript(pubKeyHash);

                // BIP-143 签名哈希
                // 注意：这里需要知道输入的金额，通常从外部传入
                // 简化版本假设金额为 0（实际使用时需要传入正确的金额）
                long amount = 0; // TODO: 需要从 UTXO 获取

                byte[] preimage = encoder.encodeBip143Preimage(tx, i, scriptCode, amount, SIGHASH_ALL);
                byte[] sigHash = hasher.hash(preimage);

                // 签名
                Signature sig = key.sign(sigHash);
                byte[] derSignature = toDerSignature(sig.bytes());

                // 添加签名类型
                byte[] signatureWithType = new byte[derSignature.length + 1];
                System.arraycopy(derSignature, 0, signatureWithType, 0, derSignature.length);
                signatureWithType[derSignature.length] = SIGHASH_ALL;

                // 创建 witness: [signature, pubkey]
                byte[][] witness = new byte[][]{signatureWithType, pubKey};

                // 更新输入（scriptSig 为空，witness 包含签名）
                signedInputs.add(new TxInput(
                        input.prevTxHash(),
                        input.prevOutputIndex(),
                        new byte[0],
                        input.sequence(),
                        witness
                ));
            }

            // 创建签名后的交易
            BtcRawTransaction signedTx = BtcRawTransaction.builder()
                    .version(tx.getVersion())
                    .lockTime(tx.getLockTime())
                    .segwit(true)
                    .build();

            // 编码交易
            byte[] rawBytes = encoder.encodeTransaction(tx, true);
            byte[] rawBytesWithoutWitness = encoder.encodeTransaction(tx, false);

            // 计算交易哈希
            byte[] txHash = hasher.computeTxid(rawBytesWithoutWitness);
            byte[] wtxid = hasher.computeWtxid(rawBytes);

            return new BtcSignedTransaction(tx, from, rawBytes, txHash, wtxid);

        } catch (Exception e) {
            throw new RuntimeException("Failed to sign SegWit transaction", e);
        }
    }

    /**
     * Legacy 签名 (P2PKH)
     */
    private BtcSignedTransaction signLegacy(BtcRawTransaction tx, SigningKey key, byte[] pubKey, String from) {
        try {
            // 为每个输入签名
            List<TxInput> signedInputs = new ArrayList<>();

            for (int i = 0; i < tx.getInputs().size(); i++) {
                TxInput input = tx.getInputs().get(i);

                // 创建签名哈希
                // 简化版本：使用输入的 scriptSig 作为 scriptPubKey
                byte[] pubKeyHash = hash160(pubKey);
                byte[] scriptPubKey = createP2PKHScript(pubKeyHash);

                // 编码用于签名的交易（替换当前输入的 scriptSig）
                byte[] sigHash = computeLegacySigHash(tx, i, scriptPubKey);

                // 签名
                Signature sig = key.sign(sigHash);
                byte[] derSignature = toDerSignature(sig.bytes());

                // 创建 scriptSig: <signature> <pubkey>
                byte[] signatureWithType = new byte[derSignature.length + 1];
                System.arraycopy(derSignature, 0, signatureWithType, 0, derSignature.length);
                signatureWithType[derSignature.length] = SIGHASH_ALL;

                ByteArrayOutputStream scriptSig = new ByteArrayOutputStream();
                scriptSig.write(signatureWithType.length);
                scriptSig.write(signatureWithType);
                scriptSig.write(pubKey.length);
                scriptSig.write(pubKey);

                signedInputs.add(new TxInput(
                        input.prevTxHash(),
                        input.prevOutputIndex(),
                        scriptSig.toByteArray(),
                        input.sequence(),
                        null
                ));
            }

            // 编码交易
            byte[] rawBytes = encoder.encodeTransaction(tx, false);

            // 计算交易哈希
            byte[] txHash = hasher.computeTxid(rawBytes);

            return new BtcSignedTransaction(tx, from, rawBytes, txHash, null);

        } catch (Exception e) {
            throw new RuntimeException("Failed to sign Legacy transaction", e);
        }
    }

    /**
     * 计算 Legacy 签名哈希
     */
    private byte[] computeLegacySigHash(BtcRawTransaction tx, int inputIndex, byte[] scriptPubKey) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // 编码交易，但替换输入的 scriptSig
        // 这里简化处理，实际需要完整实现
        byte[] encoded = encoder.encodeForSigning(tx);

        baos.write(encoded);
        // 添加 hash type (4 bytes, little-endian)
        baos.write(SIGHASH_ALL);
        baos.write(0);
        baos.write(0);
        baos.write(0);

        return hasher.hash(baos.toByteArray());
    }

    /**
     * 创建 P2PKH 脚本
     */
    private byte[] createP2PKHScript(byte[] pubKeyHash) {
        byte[] script = new byte[25];
        script[0] = 0x76; // OP_DUP
        script[1] = (byte) 0xa9; // OP_HASH160
        script[2] = 0x14; // Push 20 bytes
        System.arraycopy(pubKeyHash, 0, script, 3, 20);
        script[23] = (byte) 0x88; // OP_EQUALVERIFY
        script[24] = (byte) 0xac; // OP_CHECKSIG
        return script;
    }

    /**
     * 将签名转换为 DER 格式
     */
    private byte[] toDerSignature(byte[] signature) {
        if (signature.length != 65) {
            throw new IllegalArgumentException("Expected 65-byte signature");
        }

        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);

        // 去除前导零
        r = stripLeadingZeros(r);
        s = stripLeadingZeros(s);

        // 如果最高位是 1，添加 0x00 前缀
        if ((r[0] & 0x80) != 0) {
            byte[] padded = new byte[r.length + 1];
            System.arraycopy(r, 0, padded, 1, r.length);
            r = padded;
        }
        if ((s[0] & 0x80) != 0) {
            byte[] padded = new byte[s.length + 1];
            System.arraycopy(s, 0, padded, 1, s.length);
            s = padded;
        }

        // DER 格式: 0x30 <total length> 0x02 <r length> <r> 0x02 <s length> <s>
        int totalLength = 2 + r.length + 2 + s.length;
        byte[] der = new byte[2 + totalLength];
        int offset = 0;

        der[offset++] = 0x30;
        der[offset++] = (byte) totalLength;
        der[offset++] = 0x02;
        der[offset++] = (byte) r.length;
        System.arraycopy(r, 0, der, offset, r.length);
        offset += r.length;
        der[offset++] = 0x02;
        der[offset++] = (byte) s.length;
        System.arraycopy(s, 0, der, offset, s.length);

        return der;
    }

    private byte[] stripLeadingZeros(byte[] data) {
        int start = 0;
        while (start < data.length - 1 && data[start] == 0) {
            start++;
        }
        if (start == 0) {
            return data;
        }
        byte[] result = new byte[data.length - start];
        System.arraycopy(data, start, result, 0, result.length);
        return result;
    }

    private byte[] compressPublicKey(byte[] publicKey) {
        if (publicKey.length == 33) {
            return publicKey;
        }
        if (publicKey.length != 65 || publicKey[0] != 0x04) {
            throw new IllegalArgumentException("Invalid public key format");
        }
        byte[] compressed = new byte[33];
        compressed[0] = (byte) ((publicKey[64] & 1) == 0 ? 0x02 : 0x03);
        System.arraycopy(publicKey, 1, compressed, 1, 32);
        return compressed;
    }

    private byte[] hash160(byte[] data) {
        byte[] sha256 = io.github.superedison.web3.crypto.hash.Sha256.hash(data);
        return ripemd160(sha256);
    }

    private byte[] ripemd160(byte[] data) {
        org.bouncycastle.crypto.digests.RIPEMD160Digest ripemd160 =
                new org.bouncycastle.crypto.digests.RIPEMD160Digest();
        ripemd160.update(data, 0, data.length);
        byte[] result = new byte[20];
        ripemd160.doFinal(result, 0);
        return result;
    }
}
