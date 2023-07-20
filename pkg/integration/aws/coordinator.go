package aws

import (
	"context"
)

func ReconcileCoordinator(ctx context.Context, isCoordinator bool) error {
	if !isCoordinator {
		logger.Info("skipping coordinator reconciliation", "isCoordinator", isCoordinator)
		return nil
	}
	discovery, err := Discover(ctx)
	if err != nil {
		return err
	}
	err = ReassignVIP(ctx, discovery)
	logger.Info("reassigned VIP", "vip", discovery.VIPAddress, "err", err)
	return err
}
