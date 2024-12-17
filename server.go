package main

import (
	"database/sql"
	"log"
	"net/http"
	"server/internal/config"
	"server/internal/handlers"
	"server/internal/middleware"
)

func main() {
	configInfo := config.LoadConfig()

	connStr := "user=" + configInfo.DBUser + " password=" + configInfo.DBPassword + " dbname=" + configInfo.DBName + " sslmode=disable port=" + configInfo.DBPort

	db, err := sql.Open("postgres", connStr)

	if err != nil {
		log.Fatalf("Error connection to database: %v", err)
	}

	defer db.Close()

	jwtHandler := &handlers.JwtHandler{DB: db}

	mux := http.NewServeMux()

	mux.HandleFunc("/getTokens", jwtHandler.GetTokens)
	mux.HandleFunc("/refreshTokens", jwtHandler.RefreshTokens)

	handler := middleware.SetJSONHeader(mux)

	log.Printf("Server starting ...")

	if err := http.ListenAndServe(":62444", handler); err != nil {
		log.Fatalf("Serve failed: %v", err)
	}
}
