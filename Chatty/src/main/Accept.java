package main;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import lib.TLS;
import lib.Util;

public class Accept implements Runnable {
	ServerSocket ss;
	// HttpSocketHandler handler;
	WSHandler ws;
	ExecutorService threadPool;
	HashMap<URI, URI> redirect;
	DB db;
	File config;
	File log;
	public int port = -1;
	public int fails = 0;
	public Accept() {
		Thread main = new Thread(this);
		// handler = new HttpSocketHandler();

		try {
			config = new File("config.txt");
			log = new File("log.txt");
			log.createNewFile();

			BufferedWriter logWrite = new BufferedWriter(new FileWriter(log, true));
			logWrite.write("starting program..\n");
			BufferedReader read = new BufferedReader(new FileReader(config));
			port = Integer.valueOf(read.readLine());
			logWrite.write("read port. going to start on " + port + "\n");
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("massive fail log didnt work");
		}

		redirect = new HashMap<>();
		main.start();
	}

	@Override
	public void run() {
		try {
			if (port == -1) {
				BufferedWriter logWrite = new BufferedWriter(new FileWriter(log, true));
				logWrite.write("port failed. check prev log.\n");
			}

			db = new DB();
			redirect.put(new URI("/"), new URI("/index.html"));
			ss = new ServerSocket(port);
			threadPool = Executors.newFixedThreadPool(100);
			ws = new WSHandler(threadPool, db);
			System.out.println(
					"Server has started on 127.0.0.1:" + port + "\r\nWaiting for a connection…");

		} catch (IOException e1) {
			e1.printStackTrace();
			fails++;
		} catch (URISyntaxException e) {
			e.printStackTrace();
			fails++;
		}
		while (true) {
			if (fails >= 100) {
				break;
			}
			try {
				Socket client = ss.accept();
				// client.setSoTimeout(5000);

				// client.setKeepAlive(true);
				// client
				System.out.println("A client connected. " + Thread.currentThread());

				TLS https = new TLS();
				https.create(client);
				boolean sBreak = true;
				if (sBreak) {
					break;
				}

				String first = Util.readLine(client.getInputStream());
				// System.out.println("acp first:" + first);
				if (first == null) {
					System.out.println("error on first!");
				} else if (first.split(" ")[1].equals("/")) {
					Util.serverFile(new URI("/"), client, redirect);
				} else {
					String[] split = first.split(" ");
					System.out.println("first " + split[1]);
					switch (split[1].split("/")[1]) {
						case "ws" :
							ws.handle(client, split);
							break;
						case "db" :
							db.handle(client, split);
							break;
						default :
							Util.serverFile(new URI(split[1]), client, redirect);
							break;
					}
				}

			} catch (Exception e2) {
				e2.printStackTrace();
				fails++;
			}

		}
		try {
			BufferedWriter logWrite = new BufferedWriter(new FileWriter(log, true));
			logWrite.write("exited main loop bad. bad. bad.\n");
		} catch (IOException e) {
			// TODO: handle exception
		}
	}
}
