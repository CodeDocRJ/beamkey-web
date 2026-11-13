package com.example.passrelay;   // change to your package

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Wire-compatible with public/proto.js. Verified against docs/test-vectors.json. Needs API 26+. */
public final class ProtocolCrypto {

    private ProtocolCrypto() {}

    private static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private static final int PAD = 128;
    private static final SecureRandom RNG = new SecureRandom();

    public static final class Session {
        public final byte[] aesKey;   // 32 bytes. Keep in memory / encrypted storage only.
        public final String sas;      // "XXXX-XXXX" - show to the user, they compare with the website
        Session(byte[] k, String s) { aesKey = k; sas = s; }
    }

    public static final class Encrypted {
        public final String id, iv, ct;   // base64url, no padding -> put straight into the {"t":"send"} message
        Encrypted(String id, String iv, String ct) { this.id = id; this.iv = iv; this.ct = ct; }
    }

    // ---------- base64url ----------
    public static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    public static byte[] unb64(String s) { return Base64.getUrlDecoder().decode(s); }

    // ---------- keys ----------
    private static ECParameterSpec p256() throws Exception {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        return ap.getParameterSpec(ECParameterSpec.class);
    }

    /** New ephemeral P-256 key pair (do this when you create a room). */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray(), out = new byte[32];
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - len, out, 32 - len, len);
        return out;
    }

    /** 65-byte uncompressed point 0x04||X||Y - this is what the server and browser expect. */
    public static byte[] publicRaw(PublicKey pub) {
        ECPoint w = ((ECPublicKey) pub).getW();
        byte[] out = new byte[65];
        out[0] = 4;
        System.arraycopy(fixed32(w.getAffineX()), 0, out, 1, 32);
        System.arraycopy(fixed32(w.getAffineY()), 0, out, 33, 32);
        return out;
    }

    public static PublicKey parsePublic(byte[] raw) throws Exception {
        if (raw.length != 65 || raw[0] != 4) throw new IllegalArgumentException("bad public key");
        ECPoint w = new ECPoint(new BigInteger(1, Arrays.copyOfRange(raw, 1, 33)),
                                new BigInteger(1, Arrays.copyOfRange(raw, 33, 65)));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, p256()));
    }

    /** Only needed for the test vectors. */
    public static PrivateKey privateFromD(byte[] d) throws Exception {
        return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, d), p256()));
    }

    // ---------- session ----------
    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
        return out;
    }

    private static byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(key, "HmacSHA256"));
        return m.doFinal(data);
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    /**
     * Call when the user approves a join request.
     * @param myPriv       your private key from generateKeyPair()
     * @param peerPubRaw   the browser's public key from the join_request message (65 bytes)
     * @param phonePubRaw  YOUR public key (publicRaw of your key pair)
     * @param browserPubRaw the browser's public key (same bytes as peerPubRaw)
     */
    public static Session derive(PrivateKey myPriv, byte[] peerPubRaw, byte[] phonePubRaw, byte[] browserPubRaw) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(myPriv);
        ka.doPhase(parsePublic(peerPubRaw), true);
        byte[] shared = ka.generateSecret();                                  // 32 bytes

        byte[] salt = sha256(concat(phonePubRaw, browserPubRaw));
        byte[] prk = hmac(salt, shared);                                      // HKDF-Extract
        byte[] info = "rcvpass-v1 aes-gcm".getBytes(StandardCharsets.UTF_8);
        byte[] key = hmac(prk, concat(info, new byte[]{1}));                  // HKDF-Expand, one block = 32 bytes

        byte[] h = sha256(concat("rcvpass-v1 sas".getBytes(StandardCharsets.UTF_8), phonePubRaw, browserPubRaw));
        long bits = 0;
        for (int i = 0; i < 5; i++) bits = (bits << 8) | (h[i] & 0xFF);
        StringBuilder sb = new StringBuilder();
        for (int i = 7; i >= 0; i--) sb.append(ALPHABET.charAt((int) ((bits >> (i * 5)) & 31)));
        return new Session(key, sb.substring(0, 4) + "-" + sb.substring(4));
    }

    // ---------- encrypt ----------
    /** Call after the biometric prompt succeeds. code = the 8-char room code (no hyphen). */
    public static Encrypted encrypt(byte[] aesKey, String code, String password) throws Exception {
        byte[] iv = new byte[12], idBytes = new byte[12];
        RNG.nextBytes(iv);
        RNG.nextBytes(idBytes);
        return encryptFixed(aesKey, code, password, iv, b64(idBytes));
    }

    /** Deterministic variant, used by the test vectors. */
    public static Encrypted encryptFixed(byte[] aesKey, String code, String password, byte[] iv, String id) throws Exception {
        byte[] pw = password.getBytes(StandardCharsets.UTF_8);
        if (pw.length > PAD - 2) throw new IllegalArgumentException("password too long (max 126 bytes)");
        byte[] plain = new byte[PAD];
        plain[0] = (byte) (pw.length >> 8);
        plain[1] = (byte) pw.length;
        System.arraycopy(pw, 0, plain, 2, pw.length);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
        c.updateAAD((code + "|" + id).getBytes(StandardCharsets.UTF_8));
        byte[] ct = c.doFinal(plain);                                         // ciphertext || 16-byte tag
        Arrays.fill(plain, (byte) 0);
        return new Encrypted(id, b64(iv), b64(ct));
    }
}
