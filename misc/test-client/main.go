package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/message"
)

func postReq(fields map[string]interface{}, url string, verificationToken string) map[string]interface{} {
	jsonBody, err := json.Marshal(fields)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+verificationToken)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("failed to read response body: %v", err)
		}
		log.Fatalf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	defer resp.Body.Close()

	var respBody map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&respBody); err != nil {
		log.Fatal(err)
	}
	return respBody
}

func main() {
	fmt.Print("Enter verification token: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	verificationToken := scanner.Text()

	fmt.Print("Enter email: ")
	scanner.Scan()
	email := scanner.Text()

	fmt.Print("Enter password: ")
	scanner.Scan()
	password := scanner.Text()

	conf := opaque.DefaultConfiguration()

	client, err := conf.Client()
	if err != nil {
		log.Fatalln(err)
	}

	initReq := client.RegistrationInit([]byte(password))
	blindedMessage, err := initReq.BlindedMessage.MarshalBinary()
	if err != nil {
		log.Fatalln(err)
	}
	initFields := map[string]interface{}{
		"blindedMessage": hex.EncodeToString(blindedMessage),
	}

	resp := postReq(initFields, "http://localhost:8080/v2/accounts/setup/init", verificationToken)

	evalMsgBytes, err := hex.DecodeString(resp["evaluatedMessage"].(string))
	if err != nil {
		log.Fatalln(err)
	}
	pksBytes, err := hex.DecodeString(resp["pks"].(string))
	if err != nil {
		log.Fatalln(err)
	}
	evalMsg := conf.OPRF.Group().NewElement()
	pks := conf.OPRF.Group().NewElement()
	if err = evalMsg.UnmarshalBinary(evalMsgBytes); err != nil {
		log.Fatalln(err)
	}
	if err = pks.UnmarshalBinary(pksBytes); err != nil {
		log.Fatalln(err)
	}

	opaqueResp := message.RegistrationResponse{
		EvaluatedMessage: evalMsg,
		Pks:              pks,
	}

	record, _ := client.RegistrationFinalize(&opaqueResp, opaque.ClientRegistrationFinalizeOptions{
		ClientIdentity: []byte(email),
	})

	publicKey, err := record.PublicKey.MarshalBinary()
	if err != nil {
		log.Fatalln(err)
	}
	recordFields := map[string]interface{}{
		"publicKey":  hex.EncodeToString(publicKey),
		"maskingKey": hex.EncodeToString(record.MaskingKey),
		"envelope":   hex.EncodeToString(record.Envelope),
	}

	resp = postReq(recordFields, "http://localhost:8080/v2/accounts/setup/finalize", verificationToken)

	log.Printf("auth token: %v", resp["authToken"])
}
