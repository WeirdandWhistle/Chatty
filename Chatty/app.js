console.log("yay!");

ws = new WebSocket("ws://localhost:9001/ws");

ws.onopen = ()=>{
	console.log("opened ws");
}

ws.onmessage =(event)=>{
	console.log("got a message",event);
}

ws.onerror =()=>{
	console.log("big fat error");
}

ws.onclose=()=>{
	console.log("ws closed");
}