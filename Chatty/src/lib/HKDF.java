package lib;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

public class HKDF {
	private static final String HMAC_ALGORITHM = "HmacSHA256"; // or HmacSHA512

	public final static byte[] zeros = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	// HKDF-Extract(salt, IKM) → PRK
	public static byte[] extract(byte[] salt, byte[] ikm)
			throws NoSuchAlgorithmException, InvalidKeyException {
		if (salt == null || salt.length == 0) {
			// If salt is not provided, use a string of HashLen zeros
			salt = new byte[32]; // 32 for SHA-256
		}

		Mac mac = Mac.getInstance(HMAC_ALGORITHM);
		mac.init(new SecretKeySpec(salt, HMAC_ALGORITHM));
		return mac.doFinal(ikm); // PRK
	}

	// HKDF-Expand(PRK, info, length) → OKM
	public static byte[] expand(byte[] prk, byte[] info, int outputLength)
			throws NoSuchAlgorithmException, InvalidKeyException {
		int hashLen = 32; // for SHA-256
		int n = (int) Math.ceil((double) outputLength / hashLen);
		if (n > 255) {
			throw new IllegalArgumentException("Cannot expand to more than 255 blocks");
		}

		byte[] okm = new byte[outputLength];
		byte[] previousT = new byte[0];
		Mac mac = Mac.getInstance(HMAC_ALGORITHM);
		mac.init(new SecretKeySpec(prk, HMAC_ALGORITHM));

		int offset = 0;
		for (int i = 1; i <= n; i++) {
			mac.reset();
			mac.update(previousT);
			if (info != null) {
				mac.update(info);
			}
			mac.update((byte) i);
			previousT = mac.doFinal();
			int toCopy = Math.min(hashLen, outputLength - offset);
			System.arraycopy(previousT, 0, okm, offset, toCopy);
			offset += toCopy;
		}

		return okm;
	}
	public static byte[] expandLabel(byte[] secret, String label, byte[] context, int length)
			throws NoSuchAlgorithmException, InvalidKeyException {
		// TLS 1.3 HKDF label format
		String fullLabel = "tls13 " + label;
		byte[] labelBytes = fullLabel.getBytes(StandardCharsets.UTF_8);
		byte[] contextBytes = (context != null) ? context : new byte[0];

		int hkdfLabelLength = 2 + 1 + labelBytes.length + 1 + contextBytes.length;
		// int hkdfLabelLength = 2 + labelBytes.length + contextBytes.length;
		ByteBuffer buffer = ByteBuffer.allocate(hkdfLabelLength);

		// Write length (uint16)
		buffer.put((byte) ((length >> 8) & 0xFF));
		buffer.put((byte) ((length) & 0xFF));

		// Write label
		buffer.put((byte) labelBytes.length);
		buffer.put(labelBytes);

		// Write context
		buffer.put((byte) contextBytes.length);
		buffer.put(contextBytes);

		byte[] hkdfLabel = buffer.array();
		return expand(secret, hkdfLabel, length);
	}
	public static void runTestCases() throws InvalidKeyException, NoSuchAlgorithmException {

		byte[] ikm = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
		byte[] salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
				0x0c};
		byte[] info = {(byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5,
				(byte) 0xf6, (byte) 0xf7, (byte) 0xf8, (byte) 0xf9};
		byte[] prk = {(byte) 0x07, (byte) 0x77, (byte) 0x09, (byte) 0x36, (byte) 0x2c, (byte) 0x2e,
				(byte) 0x32, (byte) 0xdf, (byte) 0x0d, (byte) 0xdc, (byte) 0x3f, (byte) 0x0d,
				(byte) 0xc4, (byte) 0x7b, (byte) 0xba, (byte) 0x63, (byte) 0x90, (byte) 0xb6,
				(byte) 0xc7, (byte) 0x3b, (byte) 0xb5, (byte) 0x0f, (byte) 0x9c, (byte) 0x31,
				(byte) 0x22, (byte) 0xec, (byte) 0x84, (byte) 0x4a, (byte) 0xd7, (byte) 0xc2,
				(byte) 0xb3, (byte) 0xe5};

		byte[] mid = extract(salt, ikm);

		System.out.println("HKDF-Test-case-1-mid: " + Hex.toHexString(mid));
		System.out.println("HKDF-Test-case-1-PKR: " + Hex.toHexString(prk));

		System.out.println("HKDF-Test-case-1-out: " + Hex.toHexString(expand(mid, info, 42)));
		System.out.println(
				"HKDF-Test-case-1-OKM: 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

	}

}
