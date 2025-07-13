package main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import lib.HttpResponse;
import lib.Util;

public class DB {

	private Object DBLock = new Object();
	private File DB;
	public int lines = 0;

	public DB() {
		try {
			DB = new File("database/main.message.txt");
			if (DB.createNewFile()) {
				lines = 0;
			} else {
				synchronized (DBLock) {

					BufferedReader reader = new BufferedReader(new FileReader(DB));

					while (reader.readLine() != null) {
						lines++;
					}
					reader.close();
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void handle(Socket client, String[] first) {
		// System.out.println("db handle " + first[1].split("/")[2]);
		try {
			switch (new URI(first[1].split("/")[2]).getPath()) {
				case "info" :
					info(client);
					break;
				case "line" :

					line(client, new URI(first[1]));

					break;
			}
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
	}

	public void info(Socket client) {

		JsonObject out = new JsonObject();
		out.addProperty("lines", lines);
		try {
			client.getOutputStream().write(new Gson().toJson(out).getBytes());
			client.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/**
	 * idexing starts at 0
	 * 
	 * @param client
	 */
	public void line(Socket client, URI url) {
		// System.out.println("0 " +
		// Util.parseQuery(url.getQuery()).get("line"));
		int line = Integer.valueOf(Util.parseQuery(url.getQuery()).get("line"));
		synchronized (DBLock) {

			try {
				BufferedReader read = new BufferedReader(new FileReader(DB));
				// System.out.println("1");
				for (int l = 0; l < line; l++) {
					// System.out.println("2");
					if (read.readLine() == null) {
						// System.out.println("3");
						HttpResponse repo = new HttpResponse();

						repo.bad();
						client.getOutputStream().write(repo.create());
						client.close();
						return;
					}
				}

				String sl = read.readLine();

				if (sl == null) {
					HttpResponse repo = new HttpResponse();
					// System.out.println("4");
					repo.bad();
					client.getOutputStream().write(repo.create());
					client.close();
					return;
				}
				// System.out.println("5");
				HttpResponse repo = new HttpResponse();
				repo.ok();
				repo.setBody(sl);

				client.getOutputStream().write(repo.create());
				client.close();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	public void all(Socket client) {
		synchronized (DBLock) {

		}
	}
	public boolean add(String s) {
		return add(s, 1);
	}
	public boolean add(String s, int numLines) {
		synchronized (DBLock) {
			try {
				FileWriter write = new FileWriter(DB, true);

				write.write(s + "\n");
				write.close();
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
		}
		lines += numLines;
		return true;
	}

}
