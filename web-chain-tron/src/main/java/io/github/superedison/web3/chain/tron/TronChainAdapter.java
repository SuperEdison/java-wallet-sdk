package io.github.superedison.web3.chain.tron;

import io.github.superedison.web3.chain.ChainAdapter;
import io.github.superedison.web3.chain.ChainType;
import io.github.superedison.web3.chain.exception.AddressException;
import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.chain.tron.internal.TronSignature;
import io.github.superedison.web3.chain.tron.message.TronMessageSigner;
import io.github.superedison.web3.chain.tron.tx.TronRawTransaction;
import io.github.superedison.web3.chain.tron.tx.TronSignedTransaction;
import io.github.superedison.web3.chain.tron.wallet.TronHDWallet;
import io.github.superedison.web3.chain.tron.wallet.TronWallet;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.SignedTransaction;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.HDWallet;
import io.github.superedison.web3.core.wallet.Wallet;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.kdf.Bip32;
import io.github.superedison.web3.crypto.mnemonic.Bip39;
import io.github.superedison.web3.crypto.util.SecureBytes;

import java.util.List;

/**
 * TRON 链适配器
 */
public final class TronChainAdapter implements ChainAdapter {

    @Override
    public ChainType getChainType() {
        return ChainType.TRON;
    }

    // ========== 地址 ==========

    @Override
    public boolean isValidAddress(String address) {
        return TronAddress.isValid(address);
    }

    @Override
    public Address parseAddress(String address) {
        // 支持 Base58Check 格式和十六进制格式
        if (address != null && (address.startsWith("41") || address.startsWith("0x41"))) {
            return TronAddress.fromHex(address);
        }
        return TronAddress.fromBase58(address);
    }

    @Override
    public Address deriveAddress(byte[] publicKey) {
        return TronAddress.fromPublicKey(publicKey);
    }

    // ========== 钱包 ==========

    @Override
    public HDWallet createHDWallet(int wordCount) {
        List<String> mnemonic = Bip39.generateMnemonic(wordCount);
        String path = ChainType.TRON.getDefaultPath();
        return fromMnemonic(mnemonic, "", path);
    }

    @Override
    public HDWallet fromMnemonic(List<String> mnemonic, String passphrase, String path) {
        String finalPath = (path == null || path.isEmpty()) ? ChainType.TRON.getDefaultPath() : path;
        byte[] seed = Bip39.mnemonicToSeed(mnemonic, passphrase != null ? passphrase : "");
        try (Bip32.ExtendedKey masterKey = Bip32.masterKeyFromSeed(seed)) {
            Bip32.ExtendedKey derivedKey = Bip32.derivePath(masterKey, finalPath);
            return new TronHDWallet(mnemonic, passphrase, finalPath, derivedKey, true);
        } finally {
            SecureBytes.secureWipe(seed);
        }
    }

    @Override
    public Wallet fromPrivateKey(byte[] privateKey) {
        return new TronWallet(null, privateKey, true);
    }

    // ========== 交易 ==========

    @Override
    public byte[] encodeTransaction(RawTransaction transaction) {
        if (!(transaction instanceof TronRawTransaction tronTx)) {
            throw new IllegalArgumentException("Expected TronRawTransaction");
        }
        return tronTx.encode();
    }

    @Override
    public byte[] hashTransaction(RawTransaction transaction) {
        if (!(transaction instanceof TronRawTransaction tronTx)) {
            throw new IllegalArgumentException("Expected TronRawTransaction");
        }
        return tronTx.hash();
    }

    @Override
    public byte[] encodeSignedTransaction(SignedTransaction transaction) {
        if (!(transaction instanceof TronSignedTransaction tronTx)) {
            throw new IllegalArgumentException("Expected TronSignedTransaction");
        }
        return tronTx.encode();
    }

    // ========== 签名 ==========

    @Override
    public byte[] hashMessage(byte[] message) {
        return TronMessageSigner.hashMessage(message);
    }

    @Override
    public Address recoverSigner(byte[] hash, Signature signature) {
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }

        byte[] sigBytes = signature.bytes();
        if (sigBytes.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes");
        }

        TronSignature tronSig = TronSignature.fromCompact(sigBytes);
        int recoveryId = tronSig.getRecoveryId();

        byte[] publicKey = Secp256k1Signer.recoverPublicKey(
                hash,
                tronSig.getR(),
                tronSig.getS(),
                recoveryId
        );

        if (publicKey == null) {
            throw new AddressException("Failed to recover public key from signature");
        }

        return TronAddress.fromPublicKey(publicKey);
    }
}
