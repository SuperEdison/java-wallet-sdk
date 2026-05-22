package io.github.superedison.web3.chain.btc;

import io.github.superedison.web3.chain.btc.address.BtcAddressType;
import io.github.superedison.web3.chain.btc.address.BtcNetwork;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction;
import io.github.superedison.web3.chain.btc.tx.BtcSignedTransaction;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 0.1.0 范围与边界测试：
 *   1. SegWit 输入 amount=0 必须立刻拒绝
 *   2. P2SH-P2WPKH 输入要写入正确的 scriptSig
 *   3. P2TR 派生入口被禁用
 */
@DisplayName("BTC 签名器 0.1.0 范围与边界")
class BtcSignerScopeTest {

    private static final byte[] PRIVATE_KEY = new byte[]{
            (byte) 0x4c, (byte) 0x0d, (byte) 0xa4, (byte) 0xf3, (byte) 0x4d, (byte) 0x5f, (byte) 0x6a, (byte) 0x88,
            (byte) 0xc6, (byte) 0x9c, (byte) 0xa4, (byte) 0xe1, (byte) 0x4d, (byte) 0x52, (byte) 0x2c, (byte) 0x8e,
            (byte) 0xbb, (byte) 0xa1, (byte) 0x09, (byte) 0xb1, (byte) 0x2b, (byte) 0x07, (byte) 0x0d, (byte) 0x14,
            (byte) 0x9d, (byte) 0x6f, (byte) 0xb5, (byte) 0x52, (byte) 0xae, (byte) 0xa9, (byte) 0x16, (byte) 0x82
    };

    /** 测试用 prev tx hash：32 字节，0..31 递增。 */
    private static byte[] fakePrevTxHash() {
        byte[] h = new byte[32];
        for (int i = 0; i < 32; i++) h[i] = (byte) i;
        return h;
    }

    /** OP_HASH160 0x14 &lt;20 bytes&gt; OP_EQUAL ——P2SH scriptPubKey 模式。 */
    private static byte[] p2shScriptPubKey(byte[] pubKeyHash20) {
        byte[] s = new byte[23];
        s[0] = (byte) 0xa9;       // OP_HASH160
        s[1] = 0x14;              // push 20
        System.arraycopy(pubKeyHash20, 0, s, 2, 20);
        s[22] = (byte) 0x87;      // OP_EQUAL
        return s;
    }

    /** OP_0 0x14 &lt;20 bytes&gt; ——原生 P2WPKH scriptPubKey。 */
    private static byte[] p2wpkhScriptPubKey(byte[] pubKeyHash20) {
        byte[] s = new byte[22];
        s[0] = 0x00;
        s[1] = 0x14;
        System.arraycopy(pubKeyHash20, 0, s, 2, 20);
        return s;
    }

    private static byte[] hash160(byte[] data) {
        byte[] sha = io.github.superedison.web3.crypto.hash.Sha256.hash(data);
        RIPEMD160Digest ripemd = new RIPEMD160Digest();
        ripemd.update(sha, 0, sha.length);
        byte[] out = new byte[20];
        ripemd.doFinal(out, 0);
        return out;
    }

    private static byte[] compressPubKey(byte[] uncompressed) {
        byte[] c = new byte[33];
        c[0] = (byte) ((uncompressed[64] & 1) == 0 ? 0x02 : 0x03);
        System.arraycopy(uncompressed, 1, c, 1, 32);
        return c;
    }

    @Nested
    @DisplayName("SegWit 输入 amount 校验")
    class SegwitAmountValidation {

        @Test
        @DisplayName("amount=0 → IllegalArgumentException，明确指向 BIP-143")
        void rejectsZeroAmount() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] compressedPubKey = compressPubKey(signer.getPublicKey());
                byte[] pubKeyHash = hash160(compressedPubKey);

                // 注意 segwit(true) 但用旧版 addInput 让 amount 默认 0
                BtcRawTransaction tx = BtcRawTransaction.builder()
                        .version(2)
                        .segwit(true)
                        .addInput(fakePrevTxHash(), 0, 0L, p2wpkhScriptPubKey(pubKeyHash))
                        .addOutput(50000L, p2wpkhScriptPubKey(pubKeyHash))
                        .build();

                BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
                assertThatThrownBy(() -> adapter.sign(tx, signer))
                        .isInstanceOf(RuntimeException.class)
                        .hasRootCauseInstanceOf(IllegalArgumentException.class)
                        .rootCause().hasMessageContaining("BIP-143");
            }
        }

        @Test
        @DisplayName("amount > 0 → 正常签名")
        void acceptsPositiveAmount() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] compressedPubKey = compressPubKey(signer.getPublicKey());
                byte[] pubKeyHash = hash160(compressedPubKey);

                BtcRawTransaction tx = BtcRawTransaction.builder()
                        .version(2)
                        .segwit(true)
                        .addInput(fakePrevTxHash(), 0, new byte[0], 0xffffffffL, null,
                                100_000L, p2wpkhScriptPubKey(pubKeyHash))
                        .addOutput(50_000L, p2wpkhScriptPubKey(pubKeyHash))
                        .build();

                BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
                BtcSignedTransaction signed = adapter.sign(tx, signer);

                assertThat(signed.rawBytes()).isNotEmpty();
            }
        }
    }

    @Nested
    @DisplayName("P2SH-P2WPKH 包裹 SegWit")
    class P2shP2wpkh {

        @Test
        @DisplayName("scriptPubKey 为 P2SH 模式时，签名输入的 scriptSig 包含 22 字节 redeemScript")
        void writesRedeemScriptInScriptSig() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] compressedPubKey = compressPubKey(signer.getPublicKey());
                byte[] pubKeyHash = hash160(compressedPubKey);
                byte[] p2shSpk = p2shScriptPubKey(hash160(p2wpkhScriptPubKey(pubKeyHash))); // P2SH(P2WPKH)

                BtcRawTransaction tx = BtcRawTransaction.builder()
                        .version(2)
                        .segwit(true)
                        .addInput(fakePrevTxHash(), 0, new byte[0], 0xffffffffL, null,
                                100_000L, p2shSpk)
                        .addOutput(50_000L, p2wpkhScriptPubKey(pubKeyHash))
                        .build();

                BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
                BtcSignedTransaction signed = adapter.sign(tx, signer);

                BtcRawTransaction.TxInput inp = signed.rawTransaction().getInputs().get(0);
                byte[] scriptSig = inp.scriptSig();

                // 期望 scriptSig: 0x16 0x00 0x14 <hash160(pubkey) 20 bytes> = 23 bytes
                assertThat(scriptSig).hasSize(23);
                assertThat(scriptSig[0]).isEqualTo((byte) 0x16);  // push 22
                assertThat(scriptSig[1]).isEqualTo((byte) 0x00);  // OP_0
                assertThat(scriptSig[2]).isEqualTo((byte) 0x14);  // push 20
                for (int i = 0; i < 20; i++) {
                    assertThat(scriptSig[3 + i]).isEqualTo(pubKeyHash[i]);
                }

                // witness 仍是 [signature, pubkey]
                assertThat(inp.witness().length).isEqualTo(2);
                assertThat(inp.witness()[1]).isEqualTo(compressedPubKey);
            }
        }

        @Test
        @DisplayName("非 P2SH-P2WPKH 的 P2SH（如多签）必须拒绝，避免静默签出无效交易")
        void rejectsForeignP2shHashes() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] compressedPubKey = compressPubKey(signer.getPublicKey());
                byte[] pubKeyHash = hash160(compressedPubKey);

                // 构造一个 P2SH scriptPubKey，但其中的 20-byte hash 是另一个公钥的派生结果（如多签 redeemScript hash），
                // 跟当前签名公钥的 P2WPKH redeemScript hash 完全无关。
                byte[] foreignHash = new byte[20];
                for (int i = 0; i < 20; i++) foreignHash[i] = (byte) (0xAB ^ i);
                byte[] foreignP2shSpk = p2shScriptPubKey(foreignHash);

                BtcRawTransaction tx = BtcRawTransaction.builder()
                        .version(2)
                        .segwit(true)
                        .addInput(fakePrevTxHash(), 0, new byte[0], 0xffffffffL, null,
                                100_000L, foreignP2shSpk)
                        .addOutput(50_000L, p2wpkhScriptPubKey(pubKeyHash))
                        .build();

                BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
                assertThatThrownBy(() -> adapter.sign(tx, signer))
                        .isInstanceOf(RuntimeException.class)
                        .hasRootCauseInstanceOf(IllegalArgumentException.class)
                        .rootCause().hasMessageContaining("Only P2SH-P2WPKH is supported");
            }
        }

        @Test
        @DisplayName("P2WPKH 的 20-byte hash 不等于当前 key 的 hash160 时必须拒绝")
        void rejectsForeignP2wpkhHash() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] compressedPubKey = compressPubKey(signer.getPublicKey());

                // 别人的 pubKeyHash（构造任意 20 字节）
                byte[] foreignHash = new byte[20];
                for (int i = 0; i < 20; i++) foreignHash[i] = (byte) (0x33 ^ i);
                byte[] foreignP2wpkh = p2wpkhScriptPubKey(foreignHash);

                BtcRawTransaction tx = BtcRawTransaction.builder()
                        .version(2)
                        .segwit(true)
                        .addInput(fakePrevTxHash(), 0, new byte[0], 0xffffffffL, null,
                                100_000L, foreignP2wpkh)
                        .addOutput(50_000L, p2wpkhScriptPubKey(hash160(compressedPubKey)))
                        .build();

                BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
                assertThatThrownBy(() -> adapter.sign(tx, signer))
                        .isInstanceOf(RuntimeException.class)
                        .hasRootCauseInstanceOf(IllegalArgumentException.class)
                        .rootCause().hasMessageContaining("P2WPKH scriptPubKey");
            }
        }

        @Test
        @DisplayName("scriptPubKey 为 P2WSH (OP_0 0x20 <32>) / P2TR (OP_1 0x20 <32>) 形态必须拒绝")
        void rejectsForeignSegwitScriptKinds() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] compressedPubKey = compressPubKey(signer.getPublicKey());
                byte[] outScript = p2wpkhScriptPubKey(hash160(compressedPubKey));

                // P2WSH 形态：0x00 0x20 <32 bytes>
                byte[] p2wshSpk = new byte[34];
                p2wshSpk[0] = 0x00;
                p2wshSpk[1] = 0x20;
                BtcRawTransaction p2wshTx = BtcRawTransaction.builder()
                        .version(2).segwit(true)
                        .addInput(fakePrevTxHash(), 0, new byte[0], 0xffffffffL, null, 100_000L, p2wshSpk)
                        .addOutput(50_000L, outScript)
                        .build();

                BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
                assertThatThrownBy(() -> adapter.sign(p2wshTx, signer))
                        .isInstanceOf(RuntimeException.class)
                        .hasRootCauseInstanceOf(IllegalArgumentException.class)
                        .rootCause().hasMessageContaining("neither P2WPKH");

                // P2TR 形态：0x51 0x20 <32 bytes>
                byte[] p2trSpk = new byte[34];
                p2trSpk[0] = 0x51;
                p2trSpk[1] = 0x20;
                BtcRawTransaction p2trTx = BtcRawTransaction.builder()
                        .version(2).segwit(true)
                        .addInput(fakePrevTxHash(), 0, new byte[0], 0xffffffffL, null, 100_000L, p2trSpk)
                        .addOutput(50_000L, outScript)
                        .build();

                assertThatThrownBy(() -> adapter.sign(p2trTx, signer))
                        .isInstanceOf(RuntimeException.class)
                        .hasRootCauseInstanceOf(IllegalArgumentException.class)
                        .rootCause().hasMessageContaining("neither P2WPKH");
            }
        }

        @Test
        @DisplayName("segwit=true 但 scriptPubKey 为空也必须拒绝（用户漏传典型错误）")
        void rejectsEmptyScriptPubKey() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] compressedPubKey = compressPubKey(signer.getPublicKey());

                BtcRawTransaction tx = BtcRawTransaction.builder()
                        .version(2)
                        .segwit(true)
                        // amount > 0 让 amount 校验通过，但 scriptPubKey 默认空
                        .addInput(fakePrevTxHash(), 0, new byte[0], 0xffffffffL, null,
                                100_000L, new byte[0])
                        .addOutput(50_000L, p2wpkhScriptPubKey(hash160(compressedPubKey)))
                        .build();

                BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
                assertThatThrownBy(() -> adapter.sign(tx, signer))
                        .isInstanceOf(RuntimeException.class)
                        .hasRootCauseInstanceOf(IllegalArgumentException.class)
                        .rootCause().hasMessageContaining("neither P2WPKH");
            }
        }

        @Test
        @DisplayName("scriptPubKey 为原生 P2WPKH 时，scriptSig 留空（不写 redeemScript）")
        void leavesScriptSigEmptyForNativeP2wpkh() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] compressedPubKey = compressPubKey(signer.getPublicKey());
                byte[] pubKeyHash = hash160(compressedPubKey);

                BtcRawTransaction tx = BtcRawTransaction.builder()
                        .version(2)
                        .segwit(true)
                        .addInput(fakePrevTxHash(), 0, new byte[0], 0xffffffffL, null,
                                100_000L, p2wpkhScriptPubKey(pubKeyHash))
                        .addOutput(50_000L, p2wpkhScriptPubKey(pubKeyHash))
                        .build();

                BtcChainAdapter adapter = new BtcChainAdapter(BtcNetwork.MAINNET);
                BtcSignedTransaction signed = adapter.sign(tx, signer);

                assertThat(signed.rawTransaction().getInputs().get(0).scriptSig()).isEmpty();
            }
        }
    }

    @Nested
    @DisplayName("P2TR 高层入口禁用")
    class P2trDisabled {

        @Test
        @DisplayName("BtcAddressEncoder.encode(P2TR) 抛 UnsupportedOperationException")
        void encoderRefusesP2tr() {
            BtcAddressEncoder encoder = new BtcAddressEncoder();
            byte[] dummyPubKey = new byte[33];
            dummyPubKey[0] = 0x02;
            BtcAddressEncoder.BtcAddressOptions opts =
                    new BtcAddressEncoder.BtcAddressOptions(BtcAddressType.P2TR, BtcNetwork.MAINNET);

            assertThatThrownBy(() -> encoder.encode(dummyPubKey, opts))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Taproot");
        }
    }
}
