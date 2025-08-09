package lib;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class TLS {

	public static final byte HANDSHAKE = 22;
	public static final byte CHNAGE_CIPHER_SPEC = 20;
	public static final byte ALERT = 21;
	public static final byte APPLICATION = 23;
	public static final byte HEART = 24;

	public static final byte HELLO_REQUEST = 0;
	public static final byte CLIENT_HELLO = 1;
	public static final byte SEVER_HELLO = 2;
	public static final byte NEW_SESSION_TICKET = 4;
	public static final byte ENCRYPTED_EXTENSIONS = 8;
	public static final byte CERTIFICATE = 11;
	public static final byte SERVER_KEY_EXCHANGE = 12;
	public static final byte CERTIFICATE_REQUEST = 13;
	public static final byte SEVER_HELLO_DONE = 14;
	public static final byte CERTIFICATE_VERIFY = 15;
	public static final byte CLIENT_KEY_EXCHANGE = 16;
	public static final byte FINSHED = 20;

	public static final byte SSL30 = 0;
	public static final byte TLS10 = 1;
	public static final byte TLS11 = 2;
	public static final byte TLS12 = 3;
	public static final byte TLS13 = 4;

	public static final int SUPPORTED_VERSION = 43;
	public static final int KEY_SHARE = 51;
	public static final int COOKIE = 44;
	public static final int SIGNATURE_ALGORITHMS = 13;
	public static final int SIGNATURE_ALGORITHMS_CERT = 50;
	public static final int SUPPORTED_GROUPS = 10;
	public static final int SERVER_NAME = 0;

	public static final byte[] TLS_AES_128_GCM_SHA256 = {0x13, 0x01};

	public static final byte[] rsa_pkcs1_sha256 = {0x04, 0x01};

	public static final String SERVER_VERIFY_CONTEXT_STRING = "TLS 1.3, server CertificateVerify";
	public static final int TAG_LENGTH = 16;
	// headers
	byte type; // 0
	byte[] version = new byte[2]; // 1-2
	byte[] length = new byte[2]; // 3-4

	KeyPair key = null;

	// body?

	public TLS create(Socket c) throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException, SignatureException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, CloneNotSupportedException {
		InputStream in = c.getInputStream();
		c.setSoTimeout(500);

		type = (byte) in.read();
		System.out.println("type:" + type);
		version[0] = (byte) in.read();
		version[1] = (byte) in.read();

		length[0] = (byte) in.read();
		length[1] = (byte) in.read();

		if (type == HANDSHAKE) {

			MessageDigest toHash = MessageDigest.getInstance("SHA256");

			byte message_type = (byte) in.read();// 5
			byte[] second_length = {(byte) in.read(), (byte) in.read(), (byte) in.read()};// 6-8
																							// 3
			toHash.update(message_type);
			toHash.update(second_length);
			int handshake_length = (int) (((second_length[0] & 0xFF) << 16)
					| ((second_length[1] & 0xFF) << 8) | ((second_length[2] & 0xFF))); // bytes

			// long

			byte[] hsd = new byte[handshake_length];
			for (int i = 0; i < handshake_length; i++) {
				hsd[i] = (byte) in.read();
			}
			toHash.update(hsd);

			int cursor = 0;
			// to keep track of the offsets of fixed values in
			// https becuase it sucks
			// this is only 1 handshake!
			// one, thats it!

			byte[] tls_version = {hsd[0], hsd[1]};
			cursor += 2; // for tls version

			byte[] random = new byte[32];
			for (int i = 0; i < random.length; i++) {
				random[i] = hsd[i + cursor];
			}

			cursor += 32; // for the random

			byte sessionLength = hsd[cursor];
			cursor += 1;// for the length
			System.out.println("sessionLength " + sessionLength);
			byte[] sessionID = new byte[sessionLength];
			for (int i = 0; i < sessionLength; i++) {
				sessionID[i] = hsd[i + cursor];
			}
			System.out.println("sessionID.length " + sessionID.length);
			cursor += sessionLength; // for the sessionID

			int cipherSLen = (((hsd[cursor] & 255) << 8) | (hsd[cursor + 1] & 255));
			cursor += 2; // for the two byte length
			byte[] cipherSuites = new byte[cipherSLen];

			for (int i = 0; i < cipherSLen; i++) {
				cipherSuites[i] = hsd[i + cursor];
			}
			cursor += cipherSLen; // for the cipsherSuite????

			byte compLen = hsd[cursor];
			cursor += 1; // for the the 1 byte length
			byte[] compList = new byte[compLen];
			for (int i = 0; i < compLen; i++) {
				compList[i] = hsd[i + cursor];
			}
			cursor += compLen; // for the entire compLen

			int extensionLen = (short) (((hsd[cursor] & 255) << 8) | (hsd[cursor + 1] & 255));
			cursor += 2; // for extension length

			int extensionEnd = cursor + extensionLen;

			HashMap<Integer, byte[]> extensions = new HashMap<>();

			while (cursor + 4 <= extensionEnd) {

				int ex_type = (((hsd[cursor] & 255) << 8) | (hsd[cursor + 1] & 255));
				cursor += 2; // for type
				int ex_len = (((hsd[cursor] & 255) << 8) | (hsd[cursor + 1] & 255));
				cursor += 2; // for length

				if (cursor + ex_len > hsd.length) {
					System.err.println(
							"Extension length out of bounds: type=" + ex_type + ", len=" + ex_len);
					break; // or throw an exception
				}

				byte[] ex = new byte[ex_len];

				for (int i = 0; i < ex_len; i++) {
					ex[i] = hsd[i + cursor];
				}

				extensions.put(ex_type, ex);

				// if (ex_type == KEY_SHARE) {
				// System.out.println("full hex dump from key share: " +
				// Hex.toHexString(ex));
				// }

				cursor += ex_len;

			}

			// time to send the server hello
			byte[] recordHeaders = {HANDSHAKE, 3, TLS13, -1, -1};// add lenght
																	// at end

			byte[] startHandshake = {SEVER_HELLO, -1, -1, -1};// add length
																// later

			byte[] version = {3, TLS12};

			byte[] serverRandom = new byte[32];
			Random r = new Random();
			for (int i = 0; i < serverRandom.length; i++) {
				r.nextBytes(serverRandom);
			}
			// sessionLen from client read
			// sessionID from client read

			// TLS_AES_128_GCM_SHA256;

			byte compressionMethod = 0;

			byte[] sv = extensions.get(SUPPORTED_VERSION);
			boolean has13 = false;
			System.out.println("length of sv " + sv.length);
			for (int i = 2; i < sv.length; i += 2) {
				System.out.println("sv i:" + i + ", 0:" + sv[i - 1] + ", 1:" + sv[i]);
				if (sv[i - 1] == (byte) 0x03 && sv[i] == (byte) 0x04) {
					System.out.println("probbly has tls 1.3");
					has13 = true;
					break;
				}
			}
			if (!has13) {
				System.out.println("doenst have tls 1.3");
				return null;
			}
			sv = new byte[]{(SUPPORTED_VERSION >> 8) & 255, (SUPPORTED_VERSION) & 255, 0, 2, 3,
					TLS13};
			// setsd the extenion supported versions to tls 1.3 or 0x0304

			byte[] sa = extensions.get(SIGNATURE_ALGORITHMS);
			boolean hasRAS256 = false;
			for (int i = 1; i < sa.length; i += 2) {
				if (sa[i - 1] == 0x08 && sa[i] == 0x04) {
					hasRAS256 = true;
					break;
				}
			}
			if (!hasRAS256) {
				System.out.println("client doesn't allow rsa_pss_rsae_sha256");
				return null;
			}
			sa = new byte[]{(SIGNATURE_ALGORITHMS >> 8) & 255, (SIGNATURE_ALGORITHMS) & 255, 0, 3,
					2, 0x08, 0x04}; // ofr rsa_pss_rase_sha256

			boolean hasX25519 = false;
			byte[] sg = extensions.get(SUPPORTED_GROUPS);
			for (int i = 1; i < sg.length; i += 2) {
				if (sg[i - 1] == 0x00 && sg[i] == 0x1d) {
					hasX25519 = true;
				}
			}
			if (!hasX25519) {
				System.out.println("doesnt suppotrt x15519");
				return null;
			}

			KeyPairGenerator dh = KeyPairGenerator.getInstance("X25519");
			key = dh.generateKeyPair();

			XECPublicKey xecPub = (XECPublicKey) key.getPublic();
			byte[] rawPubKey = xecPub.getU().toByteArray(); // 32 bytes

			System.out.println("key length:" + rawPubKey.length);
			byte[] ks = {(KEY_SHARE >> 8) & 255, (KEY_SHARE & 255), 0, 36, 0, 0x1d, 0, 32};
			ks = Util.add(ks, rawPubKey);
			byte[] ex = Util.add(sv, ks);
			byte[] clientPubKey = extensions.get(KEY_SHARE);

			ByteBuffer buf = ByteBuffer.wrap(clientPubKey);

			int groupID = buf.getShort();
			while (buf.hasRemaining()) {
				groupID = buf.getShort() & 0xFFFF;

				if (groupID == 0x001D) {
					break;
				}
				int discardLen = buf.getShort() & 0xFFFF;
				System.out.println("advace buffer " + discardLen);
				buf.position(buf.position() + discardLen);
			}

			if (groupID == 0x001D) {
				int keyLen = buf.getShort() & 0xFFFF;

				clientPubKey = new byte[keyLen];
				buf.get(clientPubKey);

			} else {
				System.err.println("couldn't find a X25519 entry in  keyshare");
				return null;
			}

			System.out.println("groupID " + groupID);
			System.out.println("clientPubKey.length " + clientPubKey.length);

			NamedParameterSpec paramSpec = NamedParameterSpec.X25519;

			ECGenParameterSpec ecSpec = new ECGenParameterSpec("X25519");

			KeyFactory kf = KeyFactory.getInstance("X25519");
			XECPublicKey clientKeyPublicKey = (XECPublicKey) kf
					.generatePublic(new XECPublicKeySpec(ecSpec, new BigInteger(1, clientPubKey)));

			XECPrivateKey secretKey = (XECPrivateKey) key.getPrivate();

			KeyAgreement ka = KeyAgreement.getInstance("X25519");

			ka.init(secretKey);
			ka.doPhase(clientKeyPublicKey, true);
			byte[] sharedSecret = ka.generateSecret();

			byte[] serverHello = Util.add(version, serverRandom);
			System.out.println("sessionLength " + sessionLength);
			serverHello = Util.add(serverHello, new byte[]{sessionLength});
			serverHello = Util.add(serverHello, sessionID);
			// serverHello = Util.add(serverHello, new byte[]{0x00, 0x02});
			serverHello = Util.add(serverHello, TLS_AES_128_GCM_SHA256);
			serverHello = Util.add(serverHello, new byte[]{compressionMethod});
			serverHello = Util.add(serverHello,
					new byte[]{(byte) ((ex.length >> 8) & 255), (byte) ((ex.length) & 255)});
			serverHello = Util.add(serverHello, ex);

			startHandshake[1] = (byte) ((serverHello.length >> 16) & 0xFF);
			startHandshake[2] = (byte) ((serverHello.length >> 8) & 0xFF);
			startHandshake[3] = (byte) (serverHello.length & 0xFF);

			int handshakeLength = startHandshake.length + serverHello.length;
			recordHeaders[3] = (byte) ((handshakeLength >> 8) & 0xFF);
			recordHeaders[4] = (byte) (handshakeLength & 0xFF);

			serverHello = Util.add(startHandshake, serverHello);

			toHash.update(serverHello);

			byte[] out = Util.add(recordHeaders, serverHello);

			System.out.println("full server hello hexdump: ");
			Util.printHexBytes(out);

			c.getOutputStream().write(out);
			c.setSoTimeout(1000);

			recordHeaders = new byte[]{APPLICATION, 0x03, TLS12, -1, -1};
			byte[] encryptedExtensions = {ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0};

			byte[] transcript_hash = ((MessageDigest) (toHash.clone())).digest();
			System.out.println("transcript_hash " + Hex.toHexString(transcript_hash));

			HKDF.runTestCases();

			KeySchedule keys = KeySchedule.getHandshake(sharedSecret, transcript_hash);

			byte[] plaintext = Util.add(encryptedExtensions, new byte[]{HANDSHAKE});
			toHash.update(encryptedExtensions);

			Cipher aes = keys.encrypt();

			int cipherLength = plaintext.length + TAG_LENGTH;

			recordHeaders[3] = (byte) ((cipherLength >> 8) & 255);
			recordHeaders[4] = (byte) (cipherLength & 255);

			aes.updateAAD(recordHeaders);

			byte[] ciphertext = aes.doFinal(plaintext);

			out = Util.add(recordHeaders, ciphertext);

			c.getOutputStream().write(out);

			System.out.println("encryptedExtensions out: " + Hex.toHexString(out));
			System.out.println("clientRandom " + Hex.toHexString(random));
			keys.debugServerSecret();

			// ------------------------------------
			byte[] cert;
			cert = Files.readAllBytes(Paths.get("cert.der"));

			System.out.println("cert.length " + cert.length);

			recordHeaders = new byte[]{APPLICATION, 0x03, TLS12, -1, -1};

			final int fullCertEntryLength = cert.length + 3 + 2;

			byte[] certifacte = {CERTIFICATE, -1, -1, -1, 0x00, // -1 = length
					(byte) ((fullCertEntryLength >> 16) & 0xFF), // first
					(byte) ((fullCertEntryLength >> 8) & 0xFF), // second
					(byte) (fullCertEntryLength & 0xFF), // third
					(byte) ((cert.length >> 16) & 0xFF), // length for the cert
					(byte) ((cert.length >> 8) & 0xFF), // stuff
					(byte) (cert.length & 0xFF)};// spoacing

			certifacte = Util.add(certifacte, cert);
			certifacte = Util.add(certifacte, new byte[]{0x00, 0x00});

			int totalLength = certifacte.length - 4;
			certifacte[1] = (byte) ((totalLength >> 16) & 0xFF);
			certifacte[2] = (byte) ((totalLength >> 8) & 0xFF);
			certifacte[3] = (byte) ((totalLength) & 0xFF);

			plaintext = Util.add(certifacte, new byte[]{HANDSHAKE});
			toHash.update(plaintext);
			// System.out.println("certifacte plaintext hexdump: " +
			// Hex.toHexString(plaintext));

			aes = keys.encrypt();

			cipherLength = plaintext.length + TAG_LENGTH;

			recordHeaders[3] = (byte) ((cipherLength >> 8) & 0xFF);
			recordHeaders[4] = (byte) ((cipherLength) & 0xFF);

			aes.updateAAD(recordHeaders);

			ciphertext = aes.doFinal(plaintext);

			out = Util.add(recordHeaders, ciphertext);

			// -----------------------------
			// System.out.println("type " + in.read());
			c.getOutputStream().write(out);

			System.out.println("cant check anything affter cert");

			recordHeaders = new byte[]{APPLICATION, 0x03, TLS12, -1, -1};

			byte[] certVerify = {CERTIFICATE_VERIFY, -1, -1, -1};

			Signature sig = Signature.getInstance("SHA256withRSA");

			String keypem = new String(Files.readAllBytes(Paths.get("key.pem")));

			keypem = keypem.replace("-----BEGIN PRIVATE KEY-----", "")
					.replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");

			PKCS8EncodedKeySpec encodedKey = new PKCS8EncodedKeySpec(
					Base64.getDecoder().decode(keypem));

			kf = KeyFactory.getInstance("RSA");

			PrivateKey secKey = kf.generatePrivate(encodedKey);

			byte[] octet = new byte[64];
			Arrays.fill(octet, (byte) 0x20);

			byte[] contextString = SERVER_VERIFY_CONTEXT_STRING.getBytes();

			byte[] hash = ((MessageDigest) (toHash.clone())).digest();

			ByteArrayOutputStream toSign = new ByteArrayOutputStream();
			toSign.write(octet);
			toSign.write(contextString);
			toSign.write(0x00);
			toSign.write(hash);

			sig.initSign(secKey);

			sig.update(toSign.toByteArray());

			byte[] signed = sig.sign();

			certVerify = Util.add(certVerify, rsa_pkcs1_sha256);
			certVerify = Util.add(certVerify, Util.add(
					new byte[]{(byte) ((signed.length >> 8) & 255), (byte) ((signed.length) & 255)},
					signed));

			int certVerifyLength = rsa_pkcs1_sha256.length + 2 + signed.length;

			// Fill bytes 1, 2, 3 of certVerify header with certVerifyLength as
			// 3-byte big-endian
			certVerify[1] = (byte) ((certVerifyLength >> 16) & 0xFF);
			certVerify[2] = (byte) ((certVerifyLength >> 8) & 0xFF);
			certVerify[3] = (byte) (certVerifyLength & 0xFF);

			plaintext = Util.add(certVerify, new byte[]{HANDSHAKE});
			toHash.update(certVerify);

			aes = keys.encrypt();

			cipherLength = plaintext.length + TAG_LENGTH;

			recordHeaders[3] = (byte) ((ciphertext.length >> 8) & 255);
			recordHeaders[4] = (byte) ((ciphertext.length) & 255);

			aes.updateAAD(recordHeaders);

			ciphertext = aes.doFinal(plaintext);

			out = Util.add(recordHeaders, ciphertext);

			// System.out.println("is socket gonna work? " +
			// c.isOutputShutdown());

			c.getOutputStream().write(out);

			byte[] finshed_key = keys.getFinishedKey();

			HMac hmac = new HMac(new SHA256Digest());

			hmac.init(new KeyParameter(finshed_key));

			byte[] mes = ((MessageDigest) (toHash.clone())).digest();
			hmac.update(mes, 0, mes.length);

			byte[] verify_data = new byte[hmac.getMacSize()];

			hmac.doFinal(verify_data, 0);

			recordHeaders = new byte[]{APPLICATION, 0x03, TLS12, -1, -1};

			byte[] finished = {FINSHED, (byte) ((verify_data.length << 16) & 0xFF),
					(byte) ((verify_data.length << 8) & 0xFF),
					(byte) ((verify_data.length) & 0xFF)};

			finished = Util.add(finished, verify_data);

			plaintext = Util.add(finished, new byte[]{HANDSHAKE});

			aes = keys.encrypt();

			cipherLength = plaintext.length + TAG_LENGTH;

			recordHeaders[3] = (byte) ((cipherLength << 8) & 0xFF);
			recordHeaders[4] = (byte) ((cipherLength) & 0xFF);

			aes.updateAAD(recordHeaders);

			ciphertext = keys.encrypt().doFinal(finished);

			out = Util.add(recordHeaders, ciphertext);

			c.getOutputStream().write(out);

			try {
				System.out.println("end out:" + in.read());
			} catch (Exception e) {
				e.printStackTrace();
			}

			// System.out.println("type" + in.read());

		}
		System.out.println("thats everything hope it worked!");
		return null;
	}
	public static byte[] encodeSeqNum(long seqNum) {
		byte[] result = new byte[12];
		for (int i = 0; i < 8; i++) {
			result[11 - i] = (byte) (seqNum >>> (8 * i));
		}
		return result;
	}

}
