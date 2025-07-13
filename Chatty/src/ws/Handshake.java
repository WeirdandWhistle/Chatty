package ws;

import java.io.IOException;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;

import lib.HttpResponse;

public class Handshake {

	public static String PUB_WS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	public static boolean go(Socket client, HashMap<String, String> headers) throws IOException {
		boolean completed = false;
		// System.out.println(/"handshake!");
		boolean upgrade = headers.get("Connection").toLowerCase().contains("upgrade");
		boolean websocket = headers.get("Upgrade").toLowerCase().contains("websocket");

		if (upgrade && websocket) {
			// System.out.println("want to handshake");
			String secKey = headers.get("Sec-WebSocket-Key");
			// System.out.println("secKey " + secKey);
			HttpResponse repo = new HttpResponse();
			repo.setCode(101, "Switching Protocols");
			repo.addHeader("Connection", "Upgrade");
			repo.addHeader("Upgrade", "websocket");
			try {
				repo.addHeader("Sec-WebSocket-Accept", Base64.getEncoder().encodeToString(
						MessageDigest.getInstance("SHA-1").digest((secKey + PUB_WS).getBytes())));

				client.getOutputStream().write(repo.create());
				completed = true;
			} catch (NoSuchAlgorithmException e) {
				System.out.println("handshake failed!");
				e.printStackTrace();
			}
		}
		// System.out.println("handshake did:" + completed);
		return completed;
	}

}
