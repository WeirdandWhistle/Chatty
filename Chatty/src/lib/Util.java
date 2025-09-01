package lib;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

public abstract class Util {

	public static String parseBody(InputStream is) {
		// System.out.println("pb in");
		StringBuilder textBuilder = new StringBuilder();
		int byteData;
		String method = null;
		try {
			BufferedReader read = new BufferedReader(new InputStreamReader(is));
			while ((byteData = read.read()) != -1) {
				// System.out.print((char) byteData);
				if (method == null && byteData == ' ') {
					method = textBuilder.toString();
				}
				textBuilder.append((char) byteData);

				if (method != null && method.equals("GET")) {
					String current = textBuilder.toString();
					// System.out.println("'" +
					// (current.substring(current.length() - 4)
					// .replace("\n", "\\n").replace("\r", "\\r")) + "'");
					if (current.substring(current.length() - 4).equals("\r\n\r\n")) {

						// System.out.println("pb out! " + method);
						return current;
					}
				}

				// System.out.println("pb mehtod:" + method);
			}
			// System.out.println("pb out!");
			String requestData = textBuilder.toString();

			return requestData;
		} catch (IOException e) {
			System.out.println("pb error");
			e.printStackTrace();
		}

		return "well that sucks man. good luck. sry there wasn't a error.";

	}
	public static String parseBody(InputStream is, String end) {
		StringBuilder textBuilder = new StringBuilder();
		int byteData;
		try {
			// System.out.println("ok better");
			InputStreamReader read = new InputStreamReader(is);
			// System.out.println("if this passice then what?");
			while ((byteData = read.read()) != -1) {

				// System.out.print((char) byteData);

				textBuilder.append((char) byteData);

				// System.out.println("that ?");
				String current = textBuilder.toString();

				// System.out.println("this ?");
				if (current.length() >= end.length()
						&& current.substring(current.length() - end.length()).equals(end)) {
					// System.out.println("🐢🐍🐉 snake:" + current
					// .substring(current.length() - end.length()).replace("\r",
					// "\\r"));
					return current;
				}
			}
			// System.out.println("im sorry what?!?!!?💀💀💀💀💀");

			// System.out.println("pb mehtod:" + method);

			// System.out.println("pb out!");
			String requestData = textBuilder.toString();

			return requestData;
		} catch (IOException e) {
			System.out.println("pb error");
			e.printStackTrace();
		}
		return null;
	}
	public static String fromBytes(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			builder.append((char) bytes[i]);
		}
		return builder.toString();
	}

	public static String memeType(File file) {
		String name = file.getName();
		String[] broke = name.split("\\.");
		if (broke.length > 1) {
			String extension = broke[broke.length - 1];
			HashMap<String, String> MIME = new HashMap<String, String>();
			MIME.put("png", "image/png");
			MIME.put("ico", "image/vnd.microsoft.icon");
			MIME.put("gif", "image/gif");
			MIME.put("js", "text/javascript");
			MIME.put("html", "text/html");
			MIME.put("css", "text/css");
			String out = MIME.get(extension);
			if (out == null) {
				out = "text/plain";
			}
			return out;
		} else {
			return "text/plain";
		}

	}
	public static byte[] add(byte[] one, byte[] two) {
		byte[] combined = new byte[one.length + two.length];

		for (int i = 0; i < combined.length; ++i) {
			combined[i] = i < one.length ? one[i] : two[i - one.length];
		}
		return combined;
	}
	public static String readLine(InputStream is) throws IOException {
		StringBuilder sb = new StringBuilder();
		int prev = -1;
		int curr;

		while ((curr = is.read()) != -1) {
			if (prev == '\r' && curr == '\n') {
				sb.setLength(sb.length() - 1); // remove the '\r'
				break;
			}
			sb.append((char) curr);
			prev = curr;
		}

		if (curr == -1 && sb.length() == 0) {
			return null; // End of stream
		}

		return sb.toString();
	}

	public static void serverFile(URI uri, Socket client, HashMap<URI, URI> redirect)
			throws IOException {
		OutputStream out = client.getOutputStream();
		if (redirect != null) {
			URI newURI = redirect.get(uri);
			if (newURI != null) {
				uri = newURI;
			}
		}

		File file = new File(uri.getPath().replaceFirst("/", ""));
		if (file.exists()) {
			// System.out.println("uri:" + file.getPath());
			HttpResponse res = new HttpResponse();
			res.setType(Util.memeType(file));
			res.setBody(Files.readAllBytes(file.toPath()));
			out.write(res.create());
		} else {

			// System.out.println("not uri:" + file.getPath());
			HttpResponse res = new HttpResponse();
			res.notFound();
			out.write(res.create());
		}
		client.close();
	}
	public static void serverFile(URI uri, Socket client) throws IOException {
		serverFile(uri, client, null);
	}
	public static HashMap<String, String> getHeaders(Scanner scan) {

		HashMap<String, String> headers = new HashMap<>();

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
		return headers;

	}
	public static HashMap<String, String> parseQuery(String query) {

		String[] allQuery = query.split("&");
		HashMap<String, String> map = new HashMap<>();

		for (String pair : allQuery) {
			String[] pear = pair.split("=");
			map.put(pear[0], pear[1]);
			// System.out.println("0 " + pear[0] + " 1 " + pear[1]);
		}

		return map;
	}

	public static void printHexBytes(byte[] arr) {
		StringBuilder sb = new StringBuilder();
		for (byte b : arr) {
			sb.append(String.format("%02X ", b));
		}
		System.out.println(sb.toString());
	}
	public void arrList(ArrayList<Byte> al, byte[] b) {
		for (byte by : b) {
			al.add(by);
		}
	}
	public static String edian(int num, int level) {
		level -= 1;
		byte x = (byte) ((num >> (level * 8)) & 0xff);

		return String.format("%02x", x);

	}
	public static byte[] xor(byte[] a, byte[] b) {
		if (a.length != b.length) {
			throw new IllegalArgumentException("length of a and b must match!");
		}

		byte[] c = new byte[a.length];
		for (int i = 0; i < b.length; i++) {
			c[i] = (byte) (a[i] ^ b[i]);
		}
		return c;
	}
	public static byte[] reverse(byte[] a) {
		byte[] reversed = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			reversed[i] = a[(a.length - 1) - i];
		}
		return reversed;
	}
}
