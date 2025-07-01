package main;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;

public class Accept implements Runnable {
	ServerSocket ss;
	HttpSocketHandler handler;

	public Accept() {
		Thread main = new Thread(this);
		handler = new HttpSocketHandler();
		main.start();
	}

	@Override
	public void run() {
		try {

			handler.redirect.put(new URI("/"), new URI("/index.html"));
			ss = new ServerSocket(9001);
			System.out.println("Server has started on 127.0.0.1:9001\r\nWaiting for a connection…");

		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		while (true) {

			try {
				Socket client = ss.accept();
				client.setSoTimeout(5000);

				// client.setKeepAlive(true);
				// client
				System.out.println("A client connected. " + Thread.currentThread());
				new Thread(() -> {
					// System.out.println("started a new client:" +
					// Thread.currentThread());
					try {
						handler.handle(client);
					} catch (Exception e3) {
						System.out.println("ERROR");
						e3.printStackTrace();
					}
				}).start();

			} catch (Exception e2) {
				e2.printStackTrace();
			}

		}
	}
}
