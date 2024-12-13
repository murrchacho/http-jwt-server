package main

import (
	"database/sql"
	"log"
	"net/http"
	"server/config"
	"server/handlers"
)

func main() {
	config := config.LoadConfig()
	connStr := "user=" + config.DBUser + " password=" + config.DBPassword + " dbname=" + config.DBName + " sslmode=disable port=" + config.DBPort

	db, err := sql.Open("postgres", connStr)

	if err != nil {
		log.Fatalf("Error connection to database: %v", err)
	}

	defer db.Close()

	jwtHandler := &handlers.JwtHandler{DB: db}

	http.HandleFunc("/getTokens", jwtHandler.GetTokens)
	http.HandleFunc("/refreshTokens", jwtHandler.RefreshTokens)

	log.Printf("Server starting on port ...")

	if err := http.ListenAndServe(":80", nil); err != nil {
		log.Fatalf("Serve failed: %v", err)
	}
}
