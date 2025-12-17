package io.github.superedison.web3.chain.solana;

import io.github.superedison.web3.chain.solana.address.SolanaAddress;
import io.github.superedison.web3.chain.solana.tx.SolanaRawTransaction;
import io.github.superedison.web3.chain.solana.tx.SolanaSignedTransaction;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Solana ChainAdapter 测试
 */
class SolanaChainAdapterTest {

    // 测试私钥
    private static final byte[] TEST_PRIVATE_KEY = new byte[32];
    static {
        for (int i = 0; i < 32; i++) {
            TEST_PRIVATE_KEY[i] = (byte) (i + 1);
        }
    }

    // System Program ID
    private static final byte[] SYSTEM_PROGRAM = new byte[32];

    @Test
    void testChainType() {
        SolanaChainAdapter adapter = new SolanaChainAdapter();
        assertThat(adapter.chainType()).isEqualTo(ChainType.SOL);
    }

    @Test
    void testTransactionBuilder() {
        byte[] recentBlockhash = new byte[32];
        byte[] feePayer = new byte[32];

        SolanaRawTransaction tx = SolanaRawTransaction.builder()
                .recentBlockhash(recentBlockhash)
                .feePayer(feePayer)
                .addAccount(feePayer, true, true)
                .addInstruction(SYSTEM_PROGRAM, List.of(0), new byte[0])
                .build();

        assertThat(tx.getRecentBlockhash()).isEqualTo(recentBlockhash);
        assertThat(tx.getFeePayer()).isEqualTo(feePayer);
        assertThat(tx.getAccounts()).hasSize(1);
        assertThat(tx.getInstructions()).hasSize(1);
    }

    @Test
    void testSignTransaction() {
        SolanaChainAdapter adapter = new SolanaChainAdapter();

        try (Ed25519Signer signer = new Ed25519Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getPublicKey();
            byte[] recentBlockhash = new byte[32];
            for (int i = 0; i < 32; i++) {
                recentBlockhash[i] = (byte) (i + 100);
            }

            SolanaRawTransaction tx = SolanaRawTransaction.builder()
                    .recentBlockhash(recentBlockhash)
                    .feePayer(publicKey)
                    .addAccount(publicKey, true, true)
                    .addInstruction(SYSTEM_PROGRAM, List.of(0), new byte[0])
                    .build();

            SolanaSignedTransaction signedTx = adapter.sign(tx, signer);

            assertThat(signedTx).isNotNull();
            assertThat(signedTx.rawTransaction()).isEqualTo(tx);
            assertThat(signedTx.signature()).hasSize(64);
            assertThat(signedTx.from()).isEqualTo(SolanaAddress.fromPublicKey(publicKey).toBase58());
            assertThat(signedTx.rawBytes()).isNotEmpty();
            assertThat(signedTx.txHash()).hasSize(64);
            assertThat(signedTx.isValid()).isTrue();
        }
    }

    @Test
    void testSignedTransactionEncoding() {
        SolanaChainAdapter adapter = new SolanaChainAdapter();

        try (Ed25519Signer signer = new Ed25519Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getPublicKey();
            byte[] recentBlockhash = new byte[32];

            SolanaRawTransaction tx = SolanaRawTransaction.builder()
                    .recentBlockhash(recentBlockhash)
                    .feePayer(publicKey)
                    .addAccount(publicKey, true, true)
                    .addInstruction(SYSTEM_PROGRAM, List.of(0), new byte[0])
                    .build();

            SolanaSignedTransaction signedTx = adapter.sign(tx, signer);

            // 测试 Base64 编码
            String base64 = signedTx.encodeBase64();
            assertThat(base64).isNotEmpty();

            // 测试 Base58 签名
            String signatureBase58 = signedTx.signatureBase58();
            assertThat(signatureBase58).isNotEmpty();

            // 测试 rawBytes 和 txHash
            byte[] rawBytes = adapter.rawBytes(signedTx);
            byte[] txHash = adapter.txHash(signedTx);

            assertThat(rawBytes).isEqualTo(signedTx.rawBytes());
            assertThat(txHash).isEqualTo(signedTx.txHash());
        }
    }

    @Test
    void testTransactionBuilderWithBase58Blockhash() {
        byte[] feePayer = new byte[32];

        // 使用 Base58 编码的 blockhash
        SolanaRawTransaction tx = SolanaRawTransaction.builder()
                .recentBlockhash("11111111111111111111111111111111")
                .feePayer(feePayer)
                .addAccount(feePayer, true, true)
                .addInstruction(SYSTEM_PROGRAM, List.of(0), new byte[0])
                .build();

        assertThat(tx.getRecentBlockhash()).hasSize(32);
    }

    @Test
    void testTransactionBuilderValidation() {
        byte[] feePayer = new byte[32];

        // 没有 blockhash 应该失败
        assertThatThrownBy(() ->
                SolanaRawTransaction.builder()
                        .feePayer(feePayer)
                        .addAccount(feePayer, true, true)
                        .addInstruction(SYSTEM_PROGRAM, List.of(0), new byte[0])
                        .build()
        ).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void testWrongSigningKeyScheme() {
        SolanaChainAdapter adapter = new SolanaChainAdapter();

        // 使用 secp256k1 私钥应该失败
        byte[] secp256k1Key = new byte[32];
        try (var signer = new io.github.superedison.web3.crypto.ecc.Secp256k1Signer(secp256k1Key)) {
            byte[] publicKey = new byte[32];
            byte[] recentBlockhash = new byte[32];

            SolanaRawTransaction tx = SolanaRawTransaction.builder()
                    .recentBlockhash(recentBlockhash)
                    .feePayer(publicKey)
                    .addAccount(publicKey, true, true)
                    .addInstruction(SYSTEM_PROGRAM, List.of(0), new byte[0])
                    .build();

            assertThatThrownBy(() -> adapter.sign(tx, signer))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Ed25519");
        }
    }
}
