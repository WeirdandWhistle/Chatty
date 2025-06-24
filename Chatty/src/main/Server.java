package main;

import java.io.IOException;
import java.net.InetSocketAddress;

import com.sun.net.httpserver.HttpServer;

public class Server {
	public HttpServer server;
	private InetSocketAddress isa;
	public Server() {
		try {
			isa = new InetSocketAddress(9000);
			server = HttpServer.create(isa, 0);
		} catch (IOException e) {
			System.out.println("server failed when starting!");
			e.printStackTrace();
			System.exit(1);
		}
	}

}
