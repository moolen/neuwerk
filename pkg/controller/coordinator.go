package controller

import (
	"context"
	"encoding/json"
	"net"
	"strconv"

	"github.com/buraksezer/olric/events"
)

type OlricNodeEvent struct {
	Kind string `json:"kind"`
}

func (c *Controller) startCoordinator() error {
	logger.Info("starting controller coordinator")
	err := c.reconcileCoordinator()
	if err != nil {
		return err
	}

	ce := c.pubsub.Subscribe(c.ctx, "cluster.events")
	go func() {
		logger.Info("starting cluster events handler")
		for {
			select {
			case <-c.ctx.Done():
				return
			case msg := <-ce.Channel():
				logger.Info("received cluster event", "channel", msg.Channel, "payload", msg.Payload)

				var ev OlricNodeEvent
				err := json.Unmarshal([]byte(msg.Payload), &ev)
				if err != nil {
					logger.Error(err, "unable to unmarshal payload into NodeEvent", "payload", msg.Payload)
					continue
				}
				logger.Info("cluster change event", "kind", ev.Kind)
				if ev.Kind == events.KindNodeJoinEvent || ev.Kind == events.KindNodeLeftEvent {
					err = c.reconcileCoordinator()
					if err != nil {
						logger.Error(err, "unable to reconcile coordonator")
					}
				}
			}
		}
	}()

	return nil
}

func (c *Controller) reconcileCoordinator() error {
	nodeName := net.JoinHostPort(c.mgmtAddr,
		strconv.Itoa(c.dbBindPort))
	var isCoordinator bool
	membs, err := c.olric.Members(context.Background())
	if err != nil {
		return err
	}
	for _, m := range membs {
		logger.V(3).Info("current member status", "name", m.Name, "coordinator", m.Coordinator, "thisnode", nodeName)
		if m.Name == nodeName && m.Coordinator {
			isCoordinator = true
		}
	}
	if c.coordinatorReconcilerFunc != nil {
		return c.coordinatorReconcilerFunc(c.ctx, isCoordinator)
	}
	return nil
}
