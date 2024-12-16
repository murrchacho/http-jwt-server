package httpResponse

import (
	"encoding/json"
	"net/http"
)

type ReponseError struct {
	Message string `default:"Something went wrong"`
}

func SendResponse(writer http.ResponseWriter, message string, statusCode int) {
	writer.WriteHeader(statusCode)

	response := ReponseError{}

	if message != "" {
		response.Message = message
	}

	json.NewEncoder(writer).Encode(response)
}
