package main;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.concurrent.ConcurrentHashMap;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class DefaultHttpHandler implements HttpHandler {

	public ConcurrentHashMap<String, Boolean> bannedPaths = new ConcurrentHashMap<>();

	@Override
	public void handle(HttpExchange exchange) {
		// gets the path with out a leading '/'
		String path = exchange.getRequestURI().getPath().substring(1);

		File file = new File(path);

		if (file.exists()) {
			try {
				if (bannedPaths.get(path) == true) {
					String repo = "ERROR 400 Unauthorized. you cant get that.\nfrom sever";
					exchange.sendResponseHeaders(401, repo.getBytes().length);
					exchange.getResponseBody().write(repo.getBytes());
					exchange.getResponseBody().close();
					return;
				}

				byte[] repo = Files.readAllBytes(file.toPath());
				exchange.sendResponseHeaders(200, repo.length);
				exchange.getResponseBody().write(repo);
				exchange.getResponseBody().close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		} else {
			String repo = "ERROR 404 Not Found. could not find file from the path:" + path
					+ "\nfrom server";
			try {
				exchange.sendResponseHeaders(404, repo.getBytes().length);
				exchange.getResponseBody().write(repo.getBytes());
				exchange.getResponseBody().close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

}
