package lib;

import java.util.ArrayList;
import java.util.Date;

public class HttpResponse {

	private int repoCode = 200;
	private String repoStat = "OK";
	private String HttpVersion = "1.1";
	private int contentLength = -1;
	private String connection = "close";
	private String contentType = "text/plain";
	private ArrayList<String[]> headers = new ArrayList<String[]>();
	private byte[] body = null;
	private Date date = new Date(System.currentTimeMillis());

	public void ok() {
		repoCode = 200;
		repoStat = "OK";
	}
	public void bad() {
		repoCode = 400;
		repoStat = "Bad Request";
	}
	public void notFound() {
		repoCode = 404;
		repoStat = "Not Found";
	}
	public void error() {
		repoCode = 500;
		repoStat = "Internal Server Error";
	}
	public void setCode(int code, String stat) {
		repoCode = code;
		repoStat = stat;
	}
	public void setCode(int code) {
		setCode(code, "");
	}
	public void setHttpVersion(double version) {
		HttpVersion = String.valueOf(version);
	}
	public void setLength(int length) {
		contentLength = length;
	}
	public void setConnection(String con) {
		connection = con;
	}
	public void setBody(String body) {
		this.body = body.getBytes();
	}
	public void setBody(byte[] bytes) {
		body = bytes;
	}
	public void setDate(Date date) {
		this.date = date;
	}
	public void setType(String type) {
		contentType = type;
	}
	public void addHeader(String key, String value) {
		headers.add(new String[]{key, value});
	}

	public byte[] create() {
		if (contentLength == -1) {
			try {
				new RuntimeException("Fine i'll do it!");
				if (body != null) {
					contentLength = body.length;
				} else {
					contentLength = 0;
				}
			} catch (RuntimeException e) {
				e.printStackTrace();
			}
		}
		String out = "HTTP/" + HttpVersion + " " + repoCode + " " + repoStat + "\r\n" + "Date: "
				+ date.toString() + "\r\n" + "Content-Length:" + contentLength + "\r\n"
				+ "Connection: " + connection + "\r\n" + "Content-type: " + contentType + "\r\n";
		for (int i = 0; i < headers.size(); i++) {
			out += headers.get(i)[0] + ": " + headers.get(i)[1] + "\r\n";
		}
		out += "\r\n";
		byte[] ret = out.getBytes();
		if (body != null) {
			ret = Util.add(ret, body);
		}

		// System.out.println("out:" + out);

		return ret;

	}

}
