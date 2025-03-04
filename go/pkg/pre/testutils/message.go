package testutils

import (
	"encoding/base64"
	"os"
)

func LoadMessage() []byte {
	messageContent, err := os.ReadFile("../../../testdata/data/message.txt")
	if err != nil {
		panic(err)
	}

	message, err := base64.StdEncoding.DecodeString(string(messageContent))
	if err != nil {
		panic(err)
	}

	return message
}
