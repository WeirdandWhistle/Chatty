package main;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Scanner;

public class HttpSocketHandler {

	HashMap<URI, URI> redirect = new HashMap<>();
	String PUB_WS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	public HttpSocketHandler() {

	}
	public void handle(String full, Socket client)
			throws IOException, URISyntaxException, NoSuchAlgorithmException {
		HashMap<String, String> headers = new HashMap<>();
		OutputStream out = client.getOutputStream();

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

	}

}
