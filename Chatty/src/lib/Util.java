package lib;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;

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
}
