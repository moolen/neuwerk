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
	bc, err := bigcache.New(ctx, bigcache.Config{
		Shards:             1024,
		LifeWindow:         time.Minute,
		CleanWindow:        30 * time.Second,
		MaxEntriesInWindow: 1000 * 10 * 60,
		MaxEntrySize:       500,
		StatsEnabled:       false,
		Verbose:            false,
		HardMaxCacheSize:   0,
		Logger:             bigcache.DefaultLogger(),
	})
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
