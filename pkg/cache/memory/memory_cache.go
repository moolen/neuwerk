package memory

import (
	"context"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/miekg/dns"
)

type Cache struct {
	data *bigcache.BigCache
}

func New(ctx context.Context) (*Cache, error) {
	bc, err := bigcache.New(ctx, bigcache.DefaultConfig(time.Minute))
	if err != nil {
		return nil, err
	}
	c := &Cache{
		data: bc,
	}
	return c, nil
}

func (c *Cache) Get(key string) (*dns.Msg, error) {
	data, err := c.data.Get(key)
	if err != nil {
		return nil, err
	}
	msg := &dns.Msg{}
	err = msg.Unpack(data)
	return msg, err
}

func (c *Cache) Put(key string, val *dns.Msg) error {
	data, err := val.Pack()
	if err != nil {
		return err
	}
	return c.data.Set(key, data)
}

func (c *Cache) Close() {

}
