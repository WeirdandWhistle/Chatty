package ws;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.ByteBuffer;

import lib.Util;

public class Frame {

	public static final byte TEXT = 1;
	public static final byte BINARY = 2;
	public static final byte CLOSE = 8;
	public static final byte PING = 9;
	public static final byte PONG = 10;
	public static final byte EXTRA_LENGTH_SMALL = 126;
	public static final byte EXTRA_LENGTH_BIG = 127;

	private boolean fin = true;
	private byte opcode = TEXT;
	private boolean mask = false;
	private byte length = 0;
	private byte[] extraLength = null;
	private byte[] body = null;

	public Frame() {

	}
	public Frame(byte[] body) {
		this.body = body;
	}

	public void setFin(boolean fin) {
		this.fin = fin;
	}
	public void setOpcode(byte opcode) {
		this.opcode = opcode;
	}
	public void setBody(String body) {
		setBody(body.getBytes());
	}
	public void setBody(byte[] body) {
		this.body = body;
		long l = this.body.length;

		if (l <= 125) {
			extraLength = null;
			length = (byte) l;
		} else if (l <= 65536) {
			length = EXTRA_LENGTH_SMALL;
			extraLength = new byte[2];
			ByteBuffer.allocate(2).putShort((short) l).flip().get(extraLength);
		} else {
			length = EXTRA_LENGTH_BIG;
			extraLength = new byte[8];
			ByteBuffer.allocate(8).putLong(l).flip().get(extraLength);
		}
	}
	public boolean getFin() {
		return fin;
	}
	public byte[] getBody() {
		return body;
	}
	public byte getOpcode() {
		return opcode;
	}
	public byte[] create() {
		byte h1;
		byte h2;
		if (fin) {
			h1 = (byte) (128 | opcode);
		} else {
			h1 = opcode;
		}
		if (mask) {
			h2 = (byte) (128 | length);
		} else {
			h2 = length;
		}

		byte[] payload = {h1, h2};

		if (extraLength != null) {
			payload = Util.add(payload, extraLength);
		}
		if (body != null) {
			payload = Util.add(payload, body);
		}

		return payload;
	}

	public static Frame get(Socket client) throws IOException {

		InputStream in = client.getInputStream();

		int b1 = in.read();
		int b2 = in.read();

		if (b1 == -1 || b2 == -1) {
			client.close();
			throw new IOException("when reading ws headers InputStream was closed?!?!?");
			// return null;
		}

		boolean fin = (b1 & 128) != 0; // 1000 0000
		int opcode = b1 & 15; // 0000 1111

		boolean mask = (b2 & 128) != 0; // 1000 0000
		int length = b2 & 127; // 0111 1111

		if (length == 126) {
			length = in.read() << 8 | in.read();
		} else if (length == 127) {
			length = 0;
			for (int i = 0; i < 8; i++) {
				length = (length << 8) | in.read();
			}
		}
		byte[] mask_key = new byte[4];
		if (mask) {
			for (int i = 0; i < 4; i++) {
				mask_key[i] = (byte) in.read();
			}
		}

		byte[] payload = new byte[length];
		if (mask) {
			for (int i = 0; i < payload.length; i++) {
				payload[i] = (byte) (in.read() ^ mask_key[i % 4]);
			}
		} else {
			for (int i = 0; i < payload.length; i++) {
				payload[i] = (byte) in.read();
			}
		}

		Frame frame = new Frame(payload);
		frame.setFin(fin);
		frame.setOpcode((byte) opcode);

		return frame;

	}
	public static Frame closing() {
		Frame frame = new Frame();
		frame.setOpcode(CLOSE);
		return frame;
	}

}
