package httpResponse

import (
	"encoding/json"
	"net/http"
)

type ReponseError struct {
	Message string
}

func SendResponse(writer http.ResponseWriter, message string, statusCode int) {
	writer.WriteHeader(statusCode)

	response := ReponseError{"Something went wrong"}

	if message != "" {
		response.Message = message
	}

	json.NewEncoder(writer).Encode(response)
}
