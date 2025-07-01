package main;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

import lib.HttpResponse;
import lib.Util;

public class HttpSocketHandler {

	HashMap<URI, URI> redirect = new HashMap<>();
	String PUB_WS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	public HttpSocketHandler() {

	}
	public void handle(Socket client)
			throws IOException, URISyntaxException, NoSuchAlgorithmException {
		HashMap<String, String> headers = new HashMap<>();
		OutputStream out = client.getOutputStream();
		InputStream in = client.getInputStream();

		String full = Util.parseBody(in);

		System.out.println(full);

		Scanner scan = new Scanner(full).useDelimiter("\r\n");
		String[] line1 = scan.nextLine().split(" ");
		URI uri = new URI(line1[1]);

		String line = null;
		boolean canRead = scan.hasNextLine();
		while (canRead) {
			canRead = scan.hasNextLine();
			line = scan.nextLine();
			// System.out.println("line:" + line);
			if (line == null || line.isEmpty()) {
				canRead = false;
			} else {
				headers.put(line.split(":", 2)[0], line.split(":", 2)[1].trim());
			}
		}

		URI newURI = redirect.get(uri);
		if (newURI != null) {
			uri = newURI;
		}

		switch (uri.toString()) {
			case "/ws" :
				boolean upgrade = headers.get("Connection").toLowerCase().contains("upgrade");
				boolean websocket = headers.get("Upgrade").toLowerCase().contains("websocket");

				if (upgrade && websocket) {
					String secKey = headers.get("Sec-WebSocket-Key");
					System.out.println("secKey " + secKey);
					HttpResponse repo = new HttpResponse();
					repo.setCode(101, "Switching Protocols");
					repo.addHeader("Connection", "Upgrade");
					repo.addHeader("Upgrade", "websocket");
					repo.addHeader("Sec-WebSocket-Accept",
							Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1")
									.digest((secKey + this.PUB_WS).getBytes())));

					out.write(repo.create());

					String message = "Hello World! nad more super duper long payload Hello World! nad more super duper long payload Hello World! nad more super duper long payload";
					byte[] payload = message.getBytes();

					// frame header?
					out.write(0x81); // 10000001 final and text

					if (payload.length <= 125) {
						System.out.println("sending payload");
						out.write(payload.length); // no masing bit set
						out.write(payload);
					} else if (payload.length <= 65536) {

						System.out.println("trying weird things!");

						out.write(126);
						out.write((payload.length >> 8) & 0xff);
						out.write(payload.length & 0xff);
						out.write(payload);

					} else {
						System.out.println("cannot send payload to long!");
					}
					System.out.println("closing websocket!");
					out.write(0x88);
					out.write(0);
					client.close();
				}
				break;
			default :
				File file = new File(uri.getPath().replaceFirst("/", ""));
				if (file.exists()) {
					System.out.println("uri:" + file.getPath());
					HttpResponse res = new HttpResponse();
					res.setType(Util.memeType(file));
					res.setBody(Files.readAllBytes(file.toPath()));
					out.write(res.create());
				} else {

					System.out.println("not uri:" + file.getPath());
					HttpResponse res = new HttpResponse();
					res.notFound();
					out.write(res.create());
				}
				client.close();
				break;
		}

	}

}
