package cache

type LayeredCache struct{}

func NewLayeredCache() (*LayeredCache, error) {
	return &LayeredCache{}, nil
}

func (c *LayeredCache) Get() {}
func (c *LayeredCache) Put() {}
