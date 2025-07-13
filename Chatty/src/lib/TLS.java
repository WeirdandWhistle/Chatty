package lib;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.XECPublicKey;
import java.util.HashMap;
import java.util.Random;

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
	// headers
	byte type; // 0
	byte[] version = new byte[2]; // 1-2
	byte[] length = new byte[2]; // 3-4

	KeyPair key = null;

	// body?

	public TLS create(Socket c) throws IOException, NoSuchAlgorithmException {
		InputStream in = c.getInputStream();

		type = (byte) in.read();
		System.out.println("type:" + type);
		version[0] = (byte) in.read();
		version[1] = (byte) in.read();

		length[0] = (byte) in.read();
		length[1] = (byte) in.read();

		if (type == HANDSHAKE) {
			byte message_type = (byte) in.read();// 5
			byte[] second_length = {(byte) in.read(), (byte) in.read(), (byte) in.read()};// 6-8
																							// 3
			int handshake_length = (int) ((second_length[0] << 16) | (second_length[1] << 8)
					| (second_length[2])); // bytes
			// long

			byte[] hsd = new byte[handshake_length];
			for (int i = 0; i < handshake_length; i++) {
				hsd[i] = (byte) in.read();
			}

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
			byte[] sessionID = new byte[sessionLength];
			for (int i = 0; i < sessionLength; i++) {
				sessionID[i] = hsd[i + cursor];
			}
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

			HashMap<Integer, byte[]> extensions = new HashMap<>();

			while (cursor + 4 <= hsd.length) {

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

				cursor += ex_len;

			}

			// time to send the server hello
			byte[] recordHeaders = {HANDSHAKE, 3, TLS12, -1, -1};// add lenght
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
			sv = new byte[]{(SUPPORTED_VERSION >> 8) & 255, (SUPPORTED_VERSION) & 255, 0, 2, 3, 4};
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

			System.out.println("ex length " + ex.length);
			Util.printHexBytes(ex);

			byte[] serverHello = Util.add(version, serverRandom);
			serverHello = Util.add(serverHello, new byte[]{sessionLength});
			serverHello = Util.add(serverHello, sessionID);
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

			byte[] out = Util.add(recordHeaders, Util.add(startHandshake, serverHello));

			c.getOutputStream().write(out);
			System.out.println("i guess it worked! ez");

			c.setSoTimeout(1000);

			// try {
			// System.out.println("more?");
			// byte type = (byte) in.read();
			// System.out.println("type " + type);
			// if (type == ALERT) {
			//
			// byte[] extra = {(byte) in.read(), (byte) in.read(), (byte)
			// in.read(),
			// (byte) in.read()};
			// byte level = (byte) in.read();
			// byte des = (byte) in.read();
			//
			// System.out.println(level + " " + des);
			// }
			// } catch (SocketTimeoutException e) {
			// System.out.println("NOPE thats it!");
			// e.printStackTrace();
			// }
			recordHeaders = new byte[]{HANDSHAKE, 0x03, TLS12, -1, -1};
			byte[] encryptedExtensions = {ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0};// add
																				// length
																				// later
			recordHeaders[3] = (byte) ((encryptedExtensions.length >> 8) & 255);
			recordHeaders[4] = (byte) (encryptedExtensions.length & 255);

			out = Util.add(recordHeaders, encryptedExtensions);

			c.getOutputStream().write(out);

			try {
				System.out.println("more?");
				byte type = (byte) in.read();
				System.out.println("type " + type);
				in.read();
				in.read();
				int length = in.read() << 8 | in.read();
				System.out.println("len " + length);
				byte[] ran = new byte[length];
				for (int i = 0; i < length; i++) {
					ran[i] = (byte) in.read();
				}
				Util.printHexBytes(ran);
			} catch (SocketTimeoutException e) {
				System.out.println("NOPE thats it!");
				e.printStackTrace();
			}

			byte[] cert;
			cert = Files.readAllBytes(new File("cert.der").toPath());

			recordHeaders = new byte[]{HANDSHAKE, 0x03, TLS12, -1, -1};

			byte[] certifacte = {CERTIFICATE, -1, -1, -1, (byte) ((cert.length >> 16) & 255),
					(byte) ((cert.length >> 8) & 255), (byte) (cert.length & 255)};

			certifacte = Util.add(certifacte, cert);
			certifacte = Util.add(certifacte, new byte[]{0x00, 0x00});

			recordHeaders[3] = (byte) ((certifacte.length >> 8) & 255);
			recordHeaders[4] = (byte) ((certifacte.length) & 255);

			int cll = 3 + cert.length + 2;
			certifacte[1] = (byte) ((cll >> 16) & 255);
			certifacte[2] = (byte) ((cll >> 8) & 255);
			certifacte[3] = (byte) ((cll) & 255);

			out = Util.add(recordHeaders, certifacte);

			System.out.println("out bytes!");
			Util.printHexBytes(out);

			c.getOutputStream().write(out);

			recordHeaders = new byte[]{HANDSHAKE, 0x03, TLS12, -1, -1};

			byte[] certVerify = {CERTIFICATE_VERIFY, -1, -1, -1};

		}
		System.out.println("thats everything hope it worked!");
		return null;
	}

}
