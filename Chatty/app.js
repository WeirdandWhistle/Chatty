console.log("main",document.getElementsByClassName("main"));
const list = document.getElementById("list");
const text = document.getElementById("text");
let connected = false;
let ws = new WebSocket("ws://localhost:9001/ws");
const main = document.getElementsByClassName("main")[0];

let pongTimer = null;

function heartbeat(){
	//console.log("ping");
	ws.send("ping");
	setTimeout(heartbeat,10000);
}
function resetPongTimer(){
	clearTimeout(pongTimer);
	pongTimer = setTimeout(()=>{
		console.log("no pong!!!!!!");
		//alert("sorry to say but somthin went wrong");
		document.getElementById("title").style.color = "red";
	},15000);
}
function filterText(text){
	return text.replaceAll("\n","");
}
function shake(element){
	element.style.animation = "none";
	element.style.border = "red 1px solid";
	element.style.animation = "shake 0.4s linear 1";
	setTimeout(()=>{
		element.style.border = "none";
		element.style.animation = "none";
	},5000);
}
//try to get open the ws again
function getWS(){
	
	if(!connected){
		console.log("tring to connect");
		ws = new WebSocket("ws://localhost:9001/ws");
		ws.onopen = ()=>{initWS();
			console.log("opened ws");
			connected = true;
			heartbeat();
			resetPongTimer();
		};
		ws.onclose =()=>{
			setTimeout(()=>{
				if(!connected){
					getWS();
				}
			},5000);}
	}else{
		console.log("out of get loop");
		return;
	}
	

}
function initWS(){ 
ws.onopen = ()=>{
	console.log("opened ws");
	connected = true;
	heartbeat();
	resetPongTimer();
} 
ws.onmessage =(event)=>{
	//console.log("got a message",event);
	if(event.data === "pong"){
		//console.log("ponged");
		document.getElementById("title").style.color = "green";
		resetPongTimer();
	} else {
		
		let scroll = main.scrollHeight - main.scrollTop  - main.clientHeight < 10
					
					
				
		
		let stuff = JSON.parse(event.data);
		list.innerHTML += `<li> ${stuff.name} - ${stuff.message}</li>`;
		
		if(scroll){
			main.scrollTop = main.scrollHeight;
		}
		
		
	}
}

ws.onerror =()=>{
	console.log("big fat error");
	document.getElementById("title").style.color = "red";
}

ws.onclose=()=>{
	connected = false;
	console.log("ws closed");
	document.getElementById("title").style.color = "red";
	getWS();
}
}
initWS();


let textbox = document.getElementsByClassName("type-here")[0];
let text_placeholder = document.getElementsByClassName("text-placeholder")[0];
//const textconfig = { attributes: true, childList: true, subtree: true, characterData: true };

//const observer = new MutationObserver((mutList,ob)=>{
//	console.log(mutList);
//});

//observer.observe(textbox, textconfig);
//console.log(textbox);
textbox.addEventListener("input",(e)=>{
	//console.log(e,"'"+textbox.innerText.replaceAll("\n","\\n")+"'");
	
	if(e.inputType === "insertParagraph"){
		console.log("thats bad!");
		e.preventDefault();
	}
	
	if(filterText(textbox.innerText) !== ""){
		text_placeholder.style.opacity = "0";
	}else{
		text_placeholder.style.opacity = "1";
	}
	
});
textbox.addEventListener("beforeinput",(e)=>{
	if(e.inputType === "insertParagraph"){
			e.preventDefault();
			sendMessage();
		}
});

function focusTextbox(){
	textbox.focus();
}
function sendMessage(){
	if(filterText(textbox.innerText) !== ""){
		let message = textbox.innerText;
		let name = "wnj";
			
		ws.send(JSON.stringify({
			message,
			name
		}));
			
		textbox.innerText = "\n";
		text_placeholder.style.opacity = "1";
	}else{
		shake(document.getElementsByClassName("text-bar")[0]);
	}
	
}

fetch("http://localhost:9001/db/info",{method: "GET"}).then(async (e)=>{
	let json = await e.json();
	
	let lines = json.lines;
	console.log(lines);
	for(let i = 0; i<lines;i++){
		await fetch("http://localhost:9001/db/line?line="+i,{method:"GET"}).then(async (e1)=>{
			console.log(i);
			let stuff = await e1.json();
			console.log(i,stuff);
			list.innerHTML += `<li> ${stuff.name} - ${stuff.message}</li>`;
			
		});
	}
	main.scrollTop = main.scrollHeight;
});


