package lib;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import com.google.gson.Gson;

public class KeySchedule {

	byte[] early_secret;
	byte[] derived_secret;
	byte[] handshake_secret;

	byte[] server_handshake_traffic_secret;
	byte[] client_handshake_traffic_secret;

	byte[] serverIV;
	byte[] serverKey;

	byte[] clientIV;
	byte[] clientKey;

	long serverSeqNum = 0;
	long clientSeqNum = 0;

	protected KeySchedule() {

	}

	public static KeySchedule getHandshake(byte[] sharedSecret, byte[] trascriptHash)
			throws InvalidKeyException, NoSuchAlgorithmException {

		final byte[] empty = "".getBytes();

		KeySchedule ks = new KeySchedule();

		ks.early_secret = HKDF.extract(HKDF.zeros, HKDF.zeros);
		System.out.println("early_serect: " + Hex.toHexString(ks.early_secret) + " zeros length "
				+ HKDF.zeros.length);
		ks.derived_secret = HKDF.expandLabel(ks.early_secret, "derived", null, 32);

		ks.handshake_secret = HKDF.extract(ks.derived_secret, sharedSecret);
		// ks.handshake_secret = HKDF.extract(sharedSecret, ks.derived_secret);

		ks.server_handshake_traffic_secret = HKDF.expandLabel(ks.handshake_secret, "s hs traffic",
				trascriptHash, 32);
		ks.client_handshake_traffic_secret = HKDF.expandLabel(ks.handshake_secret, "c hs traffic",
				trascriptHash, 32);

		ks.serverKey = HKDF.expandLabel(ks.server_handshake_traffic_secret, "key", null, 16);
		ks.serverIV = HKDF.expandLabel(ks.server_handshake_traffic_secret, "iv", null, 12);

		ks.clientKey = HKDF.expandLabel(ks.client_handshake_traffic_secret, "key", null, 16);
		ks.clientIV = HKDF.expandLabel(ks.client_handshake_traffic_secret, "iv", null, 12);

		String json = new Gson().toJson(ks, KeySchedule.class);

		System.out.println(json);

		return ks;
	}

	public Cipher encrypt() throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher AES = Cipher.getInstance("AES/GCM/NoPadding");

		byte[] nonce = Util.xor(serverIV, encodeSeqNum(serverSeqNum));
		// Util.printHexBytes(encodeSeqNum(serverSeqNum));

		GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
		SecretKey key = new SecretKeySpec(serverKey, "AES");

		AES.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

		serverSeqNum++;
		return AES;
	}
	public Cipher encryptDebug() throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher AES = Cipher.getInstance("AES/GCM/NoPadding");

		byte[] nonce = Util.xor(serverIV, encodeSeqNum(--serverSeqNum));

		GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
		SecretKey key = new SecretKeySpec(serverKey, "AES");

		AES.init(Cipher.DECRYPT_MODE, key, gcmSpec);

		return AES;
	}
	public Cipher decrypt() throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher AES = Cipher.getInstance("AES/GCM/NoPadding");

		byte[] nonce = Util.xor(encodeSeqNum(clientSeqNum), clientIV);
		GCMParameterSpec gmcSpec = new GCMParameterSpec(128, nonce);
		SecretKey key = new SecretKeySpec(clientKey, "AES");

		AES.init(Cipher.DECRYPT_MODE, key, gmcSpec);

		clientSeqNum++;
		return AES;
	}
	public void debugServerSecret() {
		System.out.println("server_handshake_traffic_secret "
				+ Hex.toHexString(server_handshake_traffic_secret));
	}
	public byte[] getFinishedKey() throws InvalidKeyException, NoSuchAlgorithmException {
		return HKDF.expandLabel(server_handshake_traffic_secret, "finished", "".getBytes(), 32);
	}
	public static byte[] encodeSeqNum(long seqNum) {
		byte[] result = new byte[12];
		for (int i = 0; i < 8; i++) {
			result[11 - i] = (byte) (seqNum >>> (8 * i));
		}
		return result;
	}

}
