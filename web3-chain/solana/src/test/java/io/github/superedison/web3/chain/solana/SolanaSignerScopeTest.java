package io.github.superedison.web3.chain.solana;

import io.github.superedison.web3.chain.solana.tx.SolanaRawTransaction;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 0.1.0 Solana 签名器范围：仅支持单 signer。
 * 多 signer 交易会让 message[0]（numRequiredSignatures）&gt; 1，
 * 而签名器只能写入 1 个签名，节点会拒绝——必须提前阻断。
 */
@DisplayName("Solana 签名器 0.1.0 范围")
class SolanaSignerScopeTest {

    private static final byte[] PRIVATE_KEY = new byte[32];
    static { for (int i = 0; i < 32; i++) PRIVATE_KEY[i] = (byte) (i + 1); }

    private static final byte[] SYSTEM_PROGRAM = new byte[32];

    @Test
    @DisplayName("多 signer 交易在 0.1.0 抛 UnsupportedOperationException")
    void multiSignerRejectedIn010() {
        try (Ed25519Signer signer = new Ed25519Signer(PRIVATE_KEY)) {
            byte[] publicKey = signer.getPublicKey();

            // 第二个签名者（公钥可随便填，断言在签名前就触发，根本走不到 Ed25519 校验）
            byte[] anotherSigner = new byte[32];
            for (int i = 0; i < 32; i++) anotherSigner[i] = (byte) (i + 50);

            byte[] recentBlockhash = new byte[32];

            SolanaRawTransaction tx = SolanaRawTransaction.builder()
                    .recentBlockhash(recentBlockhash)
                    .feePayer(publicKey)
                    .addAccount(publicKey, true, true)        // signer #1
                    .addAccount(anotherSigner, true, true)    // signer #2 —— 触发多 signer
                    .addInstruction(SYSTEM_PROGRAM, List.of(0, 1), new byte[0])
                    .build();

            SolanaChainAdapter adapter = new SolanaChainAdapter();

            assertThatThrownBy(() -> adapter.sign(tx, signer))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("single-signer");
        }
    }
}
