package app

import (
	"context"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/target"
)

type endpointSource struct {
	inner target.Source
}

func (source *endpointSource) Next(ctx context.Context) (model.Endpoint, error) {
	parsed, err := source.inner.Next(ctx)
	if err != nil {
		return model.Endpoint{}, err
	}
	endpoint, err := target.Endpoint(parsed)
	if err != nil {
		return model.Endpoint{}, invalidError("invalid target", err)
	}
	return endpoint, nil
}

func (source *endpointSource) Close() error {
	if source == nil || source.inner == nil {
		return nil
	}
	return source.inner.Close()
}
