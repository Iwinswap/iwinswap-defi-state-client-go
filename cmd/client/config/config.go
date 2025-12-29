package config

import (
	"math/big"
	"os"

	"gopkg.in/yaml.v3"
)

type ClientConfig struct {
	ChainID        *big.Int `yaml:"chain_id"`
	StateStreamURL string   `yaml:"state_stream_url"`
}

// LoadConfig reads a configuration file from the given path and unmarshals it
// into a ClientConfig struct.
func LoadConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
