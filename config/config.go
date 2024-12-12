package config

import "os"

type Config struct {
	DBUser     string
	DBName     string
	DBPort     string
	DBPassword string
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return defaultValue
}

func LoadConfig() *Config {
	return &Config{
		DBUser:     getEnv("DBUser", "user"),
		DBName:     getEnv("DBName", "go-http"),
		DBPort:     getEnv("DBPort", "5433"),
		DBPassword: getEnv("DBPassword", "221100"),
	}
}
