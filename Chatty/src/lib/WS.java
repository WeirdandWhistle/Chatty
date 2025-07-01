package lib;

import java.nio.ByteBuffer;

public class WS {

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
			payload = Util.add(payload, body);

			return payload;
		}

	}

}
