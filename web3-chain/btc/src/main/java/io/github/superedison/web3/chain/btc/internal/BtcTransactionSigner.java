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
     * SegWit 签名（P2WPKH 与 P2SH-P2WPKH）。
     *
     * <p>P2SH-P2WPKH 的检测：若 input.scriptPubKey() 是 P2SH 模式
     * （OP_HASH160 0x14 &lt;20 bytes&gt; OP_EQUAL，即 23 字节，0xa9 0x14 ... 0x87），
     * 则 scriptSig 写入 push 22-byte redeemScript (0x16 0x00 0x14 hash160(pubkey))；
     * 否则视为原生 P2WPKH，scriptSig 留空。两者的 BIP-143 preimage 和 witness 完全相同。
     */
    private BtcSignedTransaction signSegwit(BtcRawTransaction tx, SigningKey key, byte[] pubKey, String from) {
        try {
            // 为每个输入签名
            List<TxInput> signedInputs = new ArrayList<>();

            for (int i = 0; i < tx.getInputs().size(); i++) {
                TxInput input = tx.getInputs().get(i);

                // BIP-143 强制：SegWit 输入必须提供正确的 UTXO 金额，否则签名哈希错误，
                // 广播会被节点拒绝。amount=0 静默放行是用户最容易踩的坑。
                long amount = input.amount();
                if (amount <= 0) {
                    throw new IllegalArgumentException(
                            "SegWit input #" + i + " requires amount > 0 (BIP-143 signature hash includes "
                                    + "the spent UTXO amount). Pass it via "
                                    + "builder.addInput(prevTxHash, prevOutputIndex, amount, scriptPubKey).");
                }

                // 创建 P2WPKH scriptCode: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
                byte[] pubKeyHash = hash160(pubKey);
                byte[] scriptCode = createP2PKHScript(pubKeyHash);

                byte[] preimage = encoder.encodeBip143Preimage(tx, i, scriptCode, amount, SIGHASH_ALL);
                byte[] sigHash = hasher.hash(preimage);

                // 签名
                Signature sig = key.sign(sigHash);
                byte[] derSignature = toDerSignature(sig.bytes());

                // 添加签名类型
                byte[] signatureWithType = new byte[derSignature.length + 1];
                System.arraycopy(derSignature, 0, signatureWithType, 0, derSignature.length);
                signatureWithType[derSignature.length] = SIGHASH_ALL;

                // witness 对 P2WPKH 与 P2SH-P2WPKH 都是 [signature, pubkey]
                byte[][] witness = new byte[][]{signatureWithType, pubKey};

                // 严格校验 scriptPubKey 必须是 P2WPKH 或 P2SH-P2WPKH，且对应的 hash 必须属于当前签名密钥。
                // 如果不强检：
                //   - P2WSH / P2TR / 其他 scriptPubKey 会静默走 P2WPKH 路径，签出无效广播；
                //   - 别人钱包的 P2WPKH 也会被签，得到大概率不能花的交易；
                //   - 空 scriptPubKey（用户漏传 amount/scriptPubKey）也会被签，结果同上。
                byte[] inputScriptPubKey = input.scriptPubKey();
                byte[] scriptSig;
                if (isP2shScriptPubKey(inputScriptPubKey)) {
                    byte[] redeemScript = buildP2wpkhRedeemScript(pubKeyHash);
                    byte[] expectedHash = hash160(redeemScript);
                    if (!matchesP2shHash(inputScriptPubKey, expectedHash)) {
                        throw new IllegalArgumentException(
                                "Input #" + i + " has a P2SH scriptPubKey whose hash does not match "
                                        + "hash160(0x00 0x14 hash160(pubkey)). Only P2SH-P2WPKH is supported in "
                                        + "0.1.0; multisig / arbitrary redeemScript P2SH spends require a separate "
                                        + "signing flow.");
                    }
                    scriptSig = buildP2shP2wpkhScriptSig(pubKeyHash);
                } else if (isP2wpkhScriptPubKey(inputScriptPubKey)) {
                    if (!matchesP2wpkhHash(inputScriptPubKey, pubKeyHash)) {
                        throw new IllegalArgumentException(
                                "Input #" + i + " has a P2WPKH scriptPubKey whose 20-byte hash does not match "
                                        + "hash160(this signing key's compressed public key). Either the wrong "
                                        + "scriptPubKey or the wrong signing key was supplied.");
                    }
                    scriptSig = new byte[0];
                } else {
                    throw new IllegalArgumentException(
                            "Input #" + i + " scriptPubKey is neither P2WPKH (OP_0 0x14 <20>) nor "
                                    + "P2SH-P2WPKH (OP_HASH160 0x14 <20> OP_EQUAL). 0.1.0 supports only those "
                                    + "two input types for SegWit signing. Pass the input's scriptPubKey via "
                                    + "builder.addInput(prevTxHash, prevOutputIndex, amount, scriptPubKey).");
                }

                signedInputs.add(new TxInput(
                        input.prevTxHash(),
                        input.prevOutputIndex(),
                        scriptSig,
                        input.sequence(),
                        witness,
                        input.amount(),
                        input.scriptPubKey()
                ));
            }

            // Bug 1 修复：用 signedInputs（含 witness 数据）和原始 outputs 构建已签名交易
            BtcRawTransaction.Builder builder = BtcRawTransaction.builder()
                    .version(tx.getVersion())
                    .lockTime(tx.getLockTime())
                    .segwit(true);

            for (TxInput si : signedInputs) {
                builder.addInput(si.prevTxHash(), si.prevOutputIndex(),
                        si.scriptSig(), si.sequence(), si.witness(),
                        si.amount(), si.scriptPubKey());
            }
            for (BtcRawTransaction.TxOutput output : tx.getOutputs()) {
                builder.addOutput(output.value(), output.scriptPubKey());
            }
            BtcRawTransaction signedTx = builder.build();

            // 编码已签名的交易（使用 signedTx，而非原始 tx）
            byte[] rawBytes = encoder.encodeTransaction(signedTx, true);
            byte[] rawBytesWithoutWitness = encoder.encodeTransaction(signedTx, false);

            // 计算交易哈希
            byte[] txHash = hasher.computeTxid(rawBytesWithoutWitness);
            byte[] wtxid = hasher.computeWtxid(rawBytes);

            return new BtcSignedTransaction(signedTx, from, rawBytes, rawBytesWithoutWitness.length, txHash, wtxid);

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

                // Bug 3 修复：优先使用输入自带的 scriptPubKey；若未提供，则从公钥推导 P2PKH 脚本
                byte[] scriptPubKey = input.scriptPubKey();
                if (scriptPubKey == null || scriptPubKey.length == 0) {
                    byte[] pubKeyHash = hash160(pubKey);
                    scriptPubKey = createP2PKHScript(pubKeyHash);
                }

                // 编码用于签名的交易（对当前输入替换 scriptSig，其他输入置空）
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
                        null,
                        input.amount(),
                        input.scriptPubKey()
                ));
            }

            // Bug 2 修复：用 signedInputs 和原始 outputs 构建已签名交易
            BtcRawTransaction.Builder builder = BtcRawTransaction.builder()
                    .version(tx.getVersion())
                    .lockTime(tx.getLockTime());

            for (TxInput si : signedInputs) {
                builder.addInput(si.prevTxHash(), si.prevOutputIndex(),
                        si.scriptSig(), si.sequence(), null,
                        si.amount(), si.scriptPubKey());
            }
            for (BtcRawTransaction.TxOutput output : tx.getOutputs()) {
                builder.addOutput(output.value(), output.scriptPubKey());
            }
            BtcRawTransaction signedTx = builder.build();

            // 编码已签名的交易（使用 signedTx，而非原始 tx）
            byte[] rawBytes = encoder.encodeTransaction(signedTx, false);

            // 计算交易哈希
            byte[] txHash = hasher.computeTxid(rawBytes);

            return new BtcSignedTransaction(signedTx, from, rawBytes, rawBytes.length, txHash, null);

        } catch (Exception e) {
            throw new RuntimeException("Failed to sign Legacy transaction", e);
        }
    }

    /**
     * 计算 Legacy 签名哈希 (BIP-143 之前的格式)
     *
     * Bug 3 修复：对于正在签名的输入，用其 scriptPubKey 替换 scriptSig；
     * 其他所有输入的 scriptSig 设为空字节数组。
     */
    private byte[] computeLegacySigHash(BtcRawTransaction tx, int inputIndex, byte[] scriptPubKey) throws IOException {
        // 构造一个临时交易：当前输入的 scriptSig = scriptPubKey，其他输入 scriptSig = 空
        BtcRawTransaction.Builder builder = BtcRawTransaction.builder()
                .version(tx.getVersion())
                .lockTime(tx.getLockTime());

        for (int i = 0; i < tx.getInputs().size(); i++) {
            TxInput orig = tx.getInputs().get(i);
            byte[] script = (i == inputIndex) ? scriptPubKey : new byte[0];
            builder.addInput(orig.prevTxHash(), orig.prevOutputIndex(),
                    script, orig.sequence(), null,
                    orig.amount(), orig.scriptPubKey());
        }
        for (BtcRawTransaction.TxOutput output : tx.getOutputs()) {
            builder.addOutput(output.value(), output.scriptPubKey());
        }
        BtcRawTransaction signingTx = builder.build();

        // 序列化（不含 witness）
        byte[] encoded = encoder.encodeTransaction(signingTx, false);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(encoded);
        // 追加 hash type (4 bytes, little-endian)
        baos.write(SIGHASH_ALL);
        baos.write(0);
        baos.write(0);
        baos.write(0);

        return hasher.hash(baos.toByteArray());
    }

    /**
     * 判断给定 scriptPubKey 是否为 P2SH 模式：
     *   OP_HASH160 (0xa9) 0x14 &lt;20 bytes&gt; OP_EQUAL (0x87) ——共 23 字节。
     */
    private static boolean isP2shScriptPubKey(byte[] scriptPubKey) {
        return scriptPubKey != null
                && scriptPubKey.length == 23
                && scriptPubKey[0] == (byte) 0xa9
                && scriptPubKey[1] == (byte) 0x14
                && scriptPubKey[22] == (byte) 0x87;
    }

    /**
     * 判断给定 scriptPubKey 是否为 P2WPKH 模式（OP_0 0x14 &lt;20 bytes&gt; ——共 22 字节）。
     * 区分于 P2WSH（OP_0 0x20 &lt;32 bytes&gt;）与 P2TR（OP_1 0x20 &lt;32 bytes&gt;）。
     */
    private static boolean isP2wpkhScriptPubKey(byte[] scriptPubKey) {
        return scriptPubKey != null
                && scriptPubKey.length == 22
                && scriptPubKey[0] == 0x00
                && scriptPubKey[1] == 0x14;
    }

    /**
     * 比较 P2WPKH scriptPubKey（0x00 0x14 &lt;20 bytes&gt;）中的 20-byte hash 是否等于 expectedHash。
     */
    private static boolean matchesP2wpkhHash(byte[] p2wpkhScriptPubKey, byte[] expectedHash) {
        if (expectedHash.length != 20) return false;
        for (int i = 0; i < 20; i++) {
            if (p2wpkhScriptPubKey[2 + i] != expectedHash[i]) return false;
        }
        return true;
    }

    /**
     * 构造 P2SH-P2WPKH 的 scriptSig：单一 push，内容是 22 字节的 redeemScript
     * (OP_0 0x14 hash160(pubkey))。
     *
     * 字节布局：0x16(=22, push length) 0x00 0x14 &lt;20 bytes&gt; ——共 23 字节。
     */
    private static byte[] buildP2shP2wpkhScriptSig(byte[] pubKeyHash) {
        byte[] scriptSig = new byte[23];
        scriptSig[0] = 0x16;        // push 22
        scriptSig[1] = 0x00;        // OP_0  (SegWit v0)
        scriptSig[2] = 0x14;        // push 20
        System.arraycopy(pubKeyHash, 0, scriptSig, 3, 20);
        return scriptSig;
    }

    /**
     * 22 字节的 P2WPKH redeemScript：OP_0 0x14 &lt;20 bytes&gt;。
     * 用于和 P2SH scriptPubKey 中的 hash 做匹配校验。
     */
    private static byte[] buildP2wpkhRedeemScript(byte[] pubKeyHash) {
        byte[] redeem = new byte[22];
        redeem[0] = 0x00;
        redeem[1] = 0x14;
        System.arraycopy(pubKeyHash, 0, redeem, 2, 20);
        return redeem;
    }

    /**
     * 比较 P2SH scriptPubKey（0xa9 0x14 &lt;20 bytes&gt; 0x87）中的 20-byte hash 是否等于 expectedHash。
     */
    private static boolean matchesP2shHash(byte[] p2shScriptPubKey, byte[] expectedHash) {
        if (expectedHash.length != 20) return false;
        for (int i = 0; i < 20; i++) {
            if (p2shScriptPubKey[2 + i] != expectedHash[i]) return false;
        }
        return true;
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
