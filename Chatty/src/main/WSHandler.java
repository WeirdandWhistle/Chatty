package main;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.util.List;
import java.util.Queue;
import java.util.Scanner;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;

import com.google.gson.Gson;

import lib.Message;
import lib.Util;
import ws.Frame;
import ws.Handshake;

public class WSHandler {
	ExecutorService threadPool;
	ClientBatch cb = null;
	DB db;

	public WSHandler(ExecutorService threadPool, DB db) {
		this.threadPool = threadPool;
		this.db = db;
	}

	public void handle(Socket client, String[] first) {
		try {
			// System.out.println("first step for handsake");
			if (first[0].equals("GET") && first[1].equals("/ws")) {
				// System.out.println("stuff:" +
				// Util.parseBody(client.getInputStream()));
				client.setSoTimeout(5000);
				// System.out
				// .println("its a pb error right?:" +
				// Util.readLine(client.getInputStream()));
				String headers = Util.parseBody(client.getInputStream(), "\r\n\r\n");
				// System.out.println("no?!?!!?");
				boolean shook = Handshake.go(client, Util.getHeaders(new Scanner(headers)));

				if (shook) {
					// System.out.println("shook!");
					if (cb == null) {
						cb = new ClientBatch(client);
						cb.start();
						System.out.println("starting batch");
					} else {
						cb.add(client);
						System.out.println("didnt need to start batch");
					}
				}

			} else {
				System.out.println("well that is weird");
			}
		} catch (Exception e) {
			// System.out.println("ok what is it?");
			e.printStackTrace();
		}

	}
	public class ClientBatch {
		public Queue<Message> messageQueue = new ConcurrentLinkedQueue<>();
		public List<Socket> client = new CopyOnWriteArrayList<Socket>();

		private Reader reader;
		private Writer writer;

		int timeout = 20;// ms
		public ClientBatch(Socket client) {
			try {
				client.setSoTimeout(timeout);
			} catch (SocketException e) {
				e.printStackTrace();
			}
			this.client.add(client);
		}
		public void add(Socket client) {
			try {
				client.setSoTimeout(timeout);
			} catch (SocketException e) {
				e.printStackTrace();
			}
			this.client.add(client);
		}
		public void remove(Socket client) {
			try {
				client.setSoTimeout(timeout);
			} catch (SocketException e) {
				e.printStackTrace();
			}
			this.client.remove(client);
		}
		public void start() {
			reader = new Reader();
			writer = new Writer();

			System.out.println("starting threads");

			threadPool.submit(reader);
			threadPool.submit(writer);
		}
		public void closeAndRemove(Socket s) {
			if (!this.client.remove(s)) {
				System.out.println("just why? theres no re4ason to not remove the socket");
			}
			try {
				s.getOutputStream().write(Frame.closing().create());
				s.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			System.out.println("closed and maybe removed a few sockest");
		}
		public void pong(Socket s) {
			Frame f = new Frame();
			f.setOpcode(Frame.PONG);
			try {
				s.getOutputStream().write(f.create());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		public class Reader implements Runnable {

			@Override
			public void run() {

				while (true) {
					for (Socket c : client) {
						Frame frame = null;
						try {
							frame = Frame.get(c);
						} catch (IOException e) {
						} // should disapear quietly for socket/inputstream
							// timeout reasons
						if (frame != null) {
							// System.out.println("opcode:" + (int)
							// frame.getOpcode()
							// + ", close frame:" + (int) Frame.CLOSE + ",
							// should close:"
							// + (frame.getOpcode() == Frame.CLOSE));
							if (frame.getOpcode() == Frame.CLOSE) {

								closeAndRemove(c);
								System.out.println(
										"closed WS connection on thread:" + Thread.currentThread());
							} else if (Util.fromBytes(frame.getBody()).equals("ping")) {
								// System.out.println("ponging");
								Frame f = new Frame();
								f.setBody("pong");
								try {
									c.getOutputStream().write(f.create());
								} catch (IOException e) {
									e.printStackTrace();
								}
							} else {

								Message mes = new Gson().fromJson(Util.fromBytes(frame.getBody()),
										Message.class);

								db.add(Util.fromBytes(frame.getBody()));

								messageQueue.offer(mes);
							}
						}
					}

					try {
						Thread.sleep(10);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}

		}
		public class Writer implements Runnable {

			@Override
			public void run() {
				while (true) {
					Message mes = messageQueue.poll();

					if (mes != null) {
						// System.out.println("sneding messages");
						Frame f = new Frame();
						f.setBody(new Gson().toJson(mes, Message.class));
						byte[] out = f.create();
						// System.out.println("mes:" + mes.message);
						for (Socket c : client) {
							try {
								c.getOutputStream().write(out);
							} catch (IOException e) {
								System.out.println("this one is not good.");
								try {
									c.close();
								} catch (IOException e1) {
									e1.printStackTrace();
								}
								client.remove(c);
								e.printStackTrace();
							}
						}
					}
					try {
						Thread.sleep(10);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}

			}
		}
	}

}
