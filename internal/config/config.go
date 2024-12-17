package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DBUser     string
	DBName     string
	DBPort     string
	DBPassword string
	ServerSalt string
	PrivateKey string
	PublicKey  string
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return defaultValue
}

func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}

	return &Config{
		DBUser:     getEnv("DBUser", "postgres"),
		DBName:     getEnv("DBName", "http-server"),
		DBPort:     getEnv("DBPort", "5432"),
		DBPassword: getEnv("DBPassword", "111"),
		ServerSalt: getEnv("SERVER_SALT", ""),
		PrivateKey: getEnv("PRIVATE_KEY", ""),
		PublicKey:  getEnv("PUBLIC_KEY", ""),
	}
}
