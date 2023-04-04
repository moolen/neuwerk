package cache

import "github.com/miekg/dns"

type Cache interface {
	Get(key string) (*dns.Msg, error)
	Put(key string, val *dns.Msg) error
	Close()
}
