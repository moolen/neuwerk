package olric

import (
	"context"
	"fmt"
	"time"

	"github.com/buraksezer/olric"
	"github.com/buraksezer/olric/config"
	"github.com/moolen/neuwerk/pkg/log"
)

var (
	logger = log.DefaultLogger
)

func init() {
	c := config.New("local")

	ctx, cancel := context.WithCancel(context.Background())
	c.Started = func() {
		defer cancel()
		logger.Info("[INFO] Olric is ready to accept connections")
	}

	db, err := olric.New(c)
	if err != nil {
		logger.Error(err, "Failed to create Olric instance")
	}

	go func() {
		err = db.Start()
		if err != nil {
			logger.Error(err, "olric.Start returned an error")
		}
	}()
	<-ctx.Done()

	e := db.NewEmbeddedClient()
	dm, err := e.NewDMap("bucket-of-arbitrary-items")
	if err != nil {
		logger.Error(err, "olric.NewDMap returned an error")
	}

	ctx, cancel = context.WithCancel(context.Background())

	// Magic starts here!
	fmt.Println("##")
	fmt.Println("Simple Put/Get on a DMap instance:")
	err = dm.Put(ctx, "my-key", "Olric Rocks!")
	if err != nil {
		logger.Error(err, "Failed to call Put")
	}

	gr, err := dm.Get(ctx, "my-key")
	if err != nil {
		logger.Error(err, "Failed to call Get")
	}

	value, err := gr.String()
	if err != nil {
		logger.Error(err, "Failed to read Get response")
	}

	fmt.Println("Response for my-key:", value)
	fmt.Println("##")

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = db.Shutdown(ctx)
	if err != nil {
		logger.Error(err, "Failed to shutdown Olric")
	}
}
