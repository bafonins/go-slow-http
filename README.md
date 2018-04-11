# Slow HTTP attack

This repository contains a custom implementation of the well known DoS attack called Slow HTTP attack, also known as slowloris. The tool was made only for educational purposes for the 2IC80 course at TU/e.

## Background

The slow HTTP attack is a denial of service attack. The attack is interesting because of its simplicity and effectiveness. The main idea of any denial of service attack is to make a remote machine, referenced as the victim/target further in the text, unavailable to its intended users. This is accomplished by flooding the victim by myriads of dummy(no one is interested in the actual response) requests, such that the bandwidth of the target is overwhelmed and the resources become unreachable.

Unlike regular bandwidth-consumption attacks, the slow HTTP attack does not require a large amount of data sent to the victim and can be performed from a single machine. What is more, the attacker can continue using the machine for surfing the web as he/she would normally do without experiencing any noticable delays. 

In order to explain the main idea of the slowloris attack, let's examine a regular HTTP GET request that is sent by the clients browser to the requested server.

```
GET / HTTP/1.1\r\n
Host: google.com\r\n
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)\r\n
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n
Accept-Language: en-us,en;q=0.5\r\n
Connection: keep-alive\r\n\r\n
```

Once this request is received by the server, it will issue a new thread from a thread pool to serve the request (speaking about Apache). In this case we simply request the homepage of `google.com`. Afterwards, the server might perform some business logic and then read static assets required to render the requested page on the clients side and eventually send it back to the client. This is a standard sequence of steps taken to serve a GET request.

As one can notice, the request has a certain format; it starts with`{HTTP method} {path} HTTP/{version}`, contains key-value pairs with some relevant information about you browser, every line ends with a sequence `\r\n`, etc. If you violate this format, the server most probably will not serve the page you requested. What is the most important part for the slow http attack is that each header ends with the carrent return and the new line characters and the end of the request must have twice of that sequence: `\r\n\r\n`. This ending sequence informs the server that the request is complete and can be processed. But what happens if you never send the last two `\r\n`, but send some random data instead? In this case the victim will keep accepting those and wait for the ending sequence. Note, that the core of the GET request are only first two lines of the example shown above. The clients can add any custom headers and those will be valid. Hence, in this way the attacker can create more connections and occupy the resources of the target server and make the application unreachable for regular users, simply because there will not any threads left to serve more clients. See the scheme below. It shows a sequence of messages send by the attacker in one connection. For successfull DoS attack there have to be more connections - the more the better.

```
  VICTIM                   ATTACKER
     |                        |
     |<---- partial req. -----|
     |         wait           |
     |<---- random value -----|
     |         wait           |
     |<---- random value -----|
     |         wait           |
     |<---- random value -----|
     |         wait           |
     |<---- random value -----|
     |         ...            |
```

Every time the victim is about to close the connection, because nothing is sent, the attacker sends a random piece of information, informing the victim that the connection must be kept opened. The client is just s . .  . . . . l . . . . . . . o . . . . . . w

## Features

- [x] Easy to configure
  - Auto mode: the tool will try to establish as many connections as possible. Because of the limitations of TCP there will be 64K connections at most (also take into account that some ports are reserver by your OS)
  - Custom mode: configure the amount of connections to be established, duration of the attack, timeout between sending messages, etc.
- [x] SOCK5 proxy support
  - If you have access to a SOCK5 proxy, you can use it to perform the attack. Also, [here](https://www.socks-proxy.net/) is the list of free proxy servers and there are others
  - Solves the issue with the TCP limitations. Simply open severals terminals and execute the tool from your machine and a proxy
- [x] Auto recovery
  - If the connection you and the server breaks, the tool will try to establish it again automatically, despite the mode the tool executes in.

## Examples

### Setup
First, since the program is written in Golang you have to install binaries for your operating system. Follow instructions listed on the official [Getting Started](https://golang.org/doc/install) page. Once, Golang is installed, clone this repository and build the program:
```
  git clone git@github.com:bafonins/go-slow-http.git
  go get golang.org/x/net/proxy // get this even if you dont plan to use socks5 proxy
  cd go-slow-http
  go build
```
From this point you are prepared to perform the slowloris attack using the tool.

### Execute
The tool comes with a set of inline parameters that can be passed to the program. These are:
```
  -a bool 
      Take all resources available automatically
  -ap string
    	The file name with varius User-Agent headers. Is optional (default "agents.txt")
  -c uint
    	The number of connections to establish with the victim (default 5)
  -d uint
    	The duration of the attack in seconds (default 600)
  -pa string
    	The address of the proxy server [host:port]
  -ppw string
    	The password for the proxy auth
  -proxy bool
    	Use sock5 proxy
  -pu string
    	The username for the proxy auth
  -s string
    	The address of the victim (default "http://localhost:8080")
  -t uint
    	The time between sending packets in every active connection in seconds (default 10)
```

Notes on the input parameters:
  - If the **-a** flag is used, the **-c** flag is ignored
  - The **-s** flag requires a port number, same for **-pa**

For example, running `./slow-http -s http://localhost:8080 -t 5 -d 600 -c 1000` will try to create 1000 tcp connections to the localhost:8080, send packets to each active connection every 5 seconds and will last for 10 minutes. To use proxy specify the `-proxy -pa 'proxy server'` flags and credentials if necessary.

The tool was tested on Apache web server and Tomcat with standard configuration of the server.

### Demo

1. Download [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
2. Download a linux distribution of your choice
3. One the vm is setup, make sure [Java](https://java.com/en/download/) is installed
4. Download and install [Tomcat](https://tomcat.apache.org/download-70.cgi)
5. Enter the Tomcat directory, `cd bin && catalina.sh start`
6. Once Tomcat is up, run the tool as explained in the **Execute** section. Note that the standard configuration of Tomcat can hold only 300 simultaneous connections, so `-c 301` should be enough
7. Try reaching the Tomcat application :)
