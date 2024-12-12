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
		DBUser:     getEnv("DBUser", "postgres"),
		DBName:     getEnv("DBName", "http-server"),
		DBPort:     getEnv("DBPort", "5432"),
		DBPassword: getEnv("DBPassword", "111"),
	}
}
