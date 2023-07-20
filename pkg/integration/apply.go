package integration

import (
	"context"

	"github.com/moolen/neuwerk/pkg/controller"
	"github.com/moolen/neuwerk/pkg/integration/aws"
)

const (
	AWS = "aws"
)

func Apply(ctx context.Context, integType string, ctrlConfig *controller.ControllerConfig) error {
	switch integType {
	case AWS:
		return aws.Apply(ctx, ctrlConfig)
	}
	return nil
}

func ReconcileCoordinator(ctx context.Context, integType string, isCoordinator bool) error {
	switch integType {
	case AWS:
		return aws.ReconcileCoordinator(ctx, isCoordinator)
	}
	return nil
}
