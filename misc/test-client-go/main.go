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
	"strings"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/message"
)

var conf = opaque.DefaultConfiguration()

func postReq(fields map[string]interface{}, url string, authToken *string) map[string]interface{} {
	jsonBody, err := json.Marshal(fields)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("request body: %+v", fields)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	if authToken != nil {
		req.Header.Set("Authorization", "Bearer "+*authToken)
	}

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

	log.Printf("response body: %+v", respBody)

	return respBody
}

func scanCredentials() (string, string) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("Enter email: ")
	scanner.Scan()
	email := scanner.Text()

	fmt.Print("Enter password: ")
	scanner.Scan()
	password := scanner.Text()

	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	return email, password
}

func register() {
	fmt.Print("Enter verification token: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	verificationToken := scanner.Text()

	email, password := scanCredentials()

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

	resp := postReq(initFields, "http://localhost:8080/v2/accounts/password/init", &verificationToken)

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

	resp = postReq(recordFields, "http://localhost:8080/v2/accounts/password/finalize", &verificationToken)

	log.Printf("auth token: %v", resp["authToken"])
}

func login() {
	email, password := scanCredentials()

	client, err := conf.Client()
	if err != nil {
		log.Fatalln(err)
	}

	initReq := client.GenerateKE1([]byte(password))
	blindedMessage, err := initReq.BlindedMessage.MarshalBinary()
	epk, err := initReq.ClientPublicKeyshare.MarshalBinary()
	if err != nil {
		log.Fatalln(err)
	}
	initFields := map[string]interface{}{
		"email":                    email,
		"blindedMessage":           hex.EncodeToString(blindedMessage),
		"clientEphemeralPublicKey": hex.EncodeToString(epk),
		"clientNonce":              hex.EncodeToString(initReq.ClientNonce),
	}

	resp := postReq(initFields, "http://localhost:8080/v2/auth/login/init", nil)

	evalMsgBytes, err := hex.DecodeString(resp["evaluatedMessage"].(string))
	if err != nil {
		log.Fatalln(err)
	}
	maskingNonce, err := hex.DecodeString(resp["maskingNonce"].(string))
	if err != nil {
		log.Fatalln(err)
	}
	maskedResponse, err := hex.DecodeString(resp["maskedResponse"].(string))
	if err != nil {
		log.Fatalln(err)
	}
	epkBytes, err := hex.DecodeString(resp["serverEphemeralPublicKey"].(string))
	if err != nil {
		log.Fatalln(err)
	}
	serverNonce, err := hex.DecodeString(resp["serverNonce"].(string))
	if err != nil {
		log.Fatalln(err)
	}
	serverMac, err := hex.DecodeString(resp["serverMac"].(string))
	if err != nil {
		log.Fatalln(err)
	}
	evalMsg := conf.OPRF.Group().NewElement()
	epkElement := conf.OPRF.Group().NewElement()
	if err = evalMsg.UnmarshalBinary(evalMsgBytes); err != nil {
		log.Fatalln(err)
	}
	if err = epkElement.UnmarshalBinary(epkBytes); err != nil {
		log.Fatalln(err)
	}

	opaqueResp := message.KE2{
		CredentialResponse: &message.CredentialResponse{
			EvaluatedMessage: evalMsg,
			MaskingNonce:     maskingNonce,
			MaskedResponse:   maskedResponse,
		},
		ServerPublicKeyshare: epkElement,
		ServerNonce:          serverNonce,
		ServerMac:            serverMac,
	}

	ke3, _, err := client.GenerateKE3(&opaqueResp, opaque.GenerateKE3Options{
		ClientIdentity: []byte(email),
	})
	if err != nil {
		log.Fatalln(err)
	}

	finalizeFields := map[string]interface{}{
		"clientMac": hex.EncodeToString(ke3.ClientMac),
	}
	akeToken := resp["akeToken"].(string)
	resp = postReq(finalizeFields, "http://localhost:8080/v2/auth/login/finalize", &akeToken)

	log.Printf("auth token: %v", resp["authToken"])
}

func main() {
	conf.KSF.Parameters = []int{2, 19456, 1}
	conf.KSF.Salt = make([]byte, 16)

	fmt.Println("1. Login")
	fmt.Println("2. Register/set password")
	fmt.Print("Choose an option (1-2): ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		login()
	case "2":
		register()
	default:
		fmt.Println("Invalid option")
	}
}
