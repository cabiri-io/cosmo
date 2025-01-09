package internal

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/akrylysov/algnhsa"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/aws/aws-lambda-go/events"
)

func TestHandler(t *testing.T) {
	logger, err := zap.NewProduction()
	require.NoError(t, err)

	r, err := NewRouter(
		WithLogger(logger),
		WithConfigFilePath("../config.test.yaml"),
		WithRouterConfigPath("../router.json"),
	)
	require.NoError(t, err)

	svr, err := r.NewServer(context.Background())
	require.NoError(t, err)

	handler := algnhsa.New(svr.HttpServer().Handler, &algnhsa.Options{
		RequestType: algnhsa.RequestTypeAPIGatewayV2,
	})
	j, err := json.Marshal(events.APIGatewayV2HTTPRequest{
		Version: "2.0",
		RawPath: "/health",
	})
	require.NoError(t, err)
	response, err := handler.Invoke(context.Background(), j)
	require.NoError(t, err)
	require.NotEmpty(t, response)
}

func TestHandlerThrowsErrorWhenConfigFileIsInvalid(t *testing.T) {
	logger, err := zap.NewProduction()
	require.NoError(t, err)

	r, err := NewRouter(
		WithLogger(logger),
		WithConfigFilePath("../config.test-invalid.yaml"),
		WithRouterConfigPath("../router.json"),
	)
	require.Error(t, err)
	require.Nil(t, r)
}
