package sentry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/kubeshark/tracer/pkg/version"
	"github.com/rs/zerolog/log"
	
)

type Request struct {
	Service string `json:"service"`
	Version string `json:"version"`
}

type DSNResponse struct {
	DSN string `json:"dsn"`
}

func GetDSN(ctx context.Context) (string, error) {

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3 // Max retry attempts

	client := retryClient.StandardClient()

	endpoint := getDSNEndpoint()

	reqBody := Request{
		Service: "tracer",
		Version: version.Ver,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("error marshalling request body: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("error creating POST request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil // Return empty string if not 200
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	var dsnResp DSNResponse
	err = json.Unmarshal(body, &dsnResp)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling response body: %v", err)
	}

	return dsnResp.DSN, nil
}

func getDSNEndpoint() string {
	apiUrl, ok := os.LookupEnv("KUBESHARK_CLOUD_API_URL")
	if !ok {
		log.Info().Msg("KUBESHARK_CLOUD_API_URL wasn't found. Defaulting to https://api.kubeshark.co")
		apiUrl = "https://api.kubeshark.co"
	}

	return fmt.Sprintf("%s/sentry", apiUrl)
}
