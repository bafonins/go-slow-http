# Slow HTTP attack

This repository contains a custom implementation of the well known DoS attack called Slow HTTP attack, also known as slowloris.

## Background

## Features

## Examples

### Setup
First, since the program is written in Golang you have to install binaries for your operating system. Follow instructions listed on the official [Getting Started](https://golang.org/doc/install) page. Once, Golang is installed, clone this repository and build the program:
```
  git clone git@github.com:bafonins/go-slow-http.git
  cd go-slow-http
  go build
```
From this point you are prepared to perform the slowloris attack using the tool.

### Execute
The tool comes with a set of inline parameters that can be passed to the program. These are:
```
  -ap string
    	The file name with varius User-Agent headers. Is optional (default "agents.txt")
  -c uint
    	The number of connections to establish with the victim (default 350)
  -d uint
    	The duration of the attack in seconds (default 600)
  -s string
    	The address of the victim (default "http://127.0.0.1:8080")
  -t uint
    	The time between sending packets in every active connection in seconds (default 10)
```

For example, running `./slow-http -s http://localhost:8080 -t 5 -d 600 -c 1000` will try to create 1000 tcp connections to the localhost:8080, send packets to each active connection every 5 seconds and will last for 10 minutes.