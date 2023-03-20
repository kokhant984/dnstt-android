package libdns

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"www.bamsoftware.com/git/dnstt.git/client"
)

type DnsPoint struct {
	Mode             int
	DnsAddress       string
	Nameserver       string
	UtlsDistribution string
	ListenAddr       string
	Pubkey           string

	DnsLog DnsEvent

	client  *client.Instance
	dnsOP   *sync.Mutex
	running bool
}

type DnsEvent interface {
	Status(string)
	Protect(int) bool
}

func NewDnsPoint(e DnsEvent) *DnsPoint {
	return &DnsPoint{
		DnsLog: e,
		dnsOP:  new(sync.Mutex),
	}
}

func (d *DnsPoint) GetIsRunning() bool {
	return d.running
}

// exists returns whether the given file or directory exists
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (d *DnsPoint) Start() error {
	d.dnsOP.Lock()
	defer d.dnsOP.Unlock()

	if !d.running {
		if d.DnsAddress == "" {
			return fmt.Errorf("DNS address cannot be empty")
		}

		if d.Nameserver == "" {
			return fmt.Errorf("Nameserver cannot be empty")
		}

		if d.Pubkey == "" {
			return fmt.Errorf("Pubkey is needed")
		}

		_, err := net.ResolveTCPAddr("tcp", d.ListenAddr)
		if err != nil {
			return err
		}

		data := &client.Data{
			Domain:     d.Nameserver,
			ListenAddr: d.ListenAddr,
		}

		switch d.Mode {
		case 0:
			data.DohURL = d.DnsAddress
		case 1:
			data.DotAddr = d.DnsAddress
		case 2:
			data.UdpAddr = d.DnsAddress
		}

		exist, err := fileExists(d.Pubkey)
		if err != nil {
			return err
		}

		if exist {
			data.PubkeyFile = d.Pubkey
		} else {
			data.PubkeyString = d.Pubkey
		}

		c := client.New(d.DnsLog)
		d.client = c
		d.client.SetData(data)

		d.running = true
		go func() {
			if err := d.client.Start(); err != nil {
				d.running = false
				log.Println(err)
			}
		}()
	}
	return nil
}

func (d *DnsPoint) Stop() error {
	d.dnsOP.Lock()
	defer d.dnsOP.Unlock()
	if d.running {
		d.client.Stop()
		d.client = nil
		d.running = false
	}
	return nil
}
