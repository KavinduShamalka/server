package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"server/proof"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/patrickmn/go-cache"
	"github.com/ugorji/go/codec"

	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/iden3/iden3comm/v2/protocol"
)

var (
	userSessionTracker = cache.New(60*time.Minute, 60*time.Minute)
	jsonHandle         codec.JsonHandle
)

func main() {
	http.HandleFunc("/api/sign-in", GetAuthRequest)
	http.HandleFunc("/api/callback", Callback)
	http.HandleFunc("/api/status", GetRequestStatus)
	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.ListenAndServe(":8080", nil)
}

// Create a map to store the auth requests and their session IDs
// var requestMap = make(map[string]interface{})

func GetAuthRequest(w http.ResponseWriter, r *http.Request) {

	// Audience is verifier id
	rURL := "https://3dbd-112-134-211-116.ngrok-free.app"
	// Store random session ID to sId
	sessionID := strconv.Itoa(rand.Intn(1000000))
	CallbackURL := "/api/callback"
	Audience := "did:polygonid:polygon:mumbai:2qG7bhdJKsk4tSbShiXiF2Eti2cVjUH3iTDXyyn6i7"

	uri := fmt.Sprintf("%s%s?sessionId=%s", rURL, CallbackURL, sessionID)

	// Generate request for basic authentication
	var request protocol.AuthorizationRequestMessage = auth.CreateAuthorizationRequest("test flow", Audience, uri)

	// request.ID = "7f38a193-0918-4a48-9fac-36adfdb8b542"
	// request.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542"

	// Add new request ID
	request.ID = uuid.New().String()
	// Add new thread ID
	request.ThreadID = uuid.New().String()

	// Set user session tracker by passing sessionID, request, and defaultExpiration using cache
	userSessionTracker.Set(sessionID, request, cache.DefaultExpiration)

	// Convert the request object into its JSON representation.
	msgBytes, _ := json.Marshal(request)

	// Add request for a specific proof
	mtpProofRequest := proof.ProofRequest()
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	// Store auth request in map associated with session ID
	// requestMap[strconv.Itoa(sessionID)] = request

	// print request
	fmt.Println(request)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Expose-Headers", "x-id")
	w.Header().Set("x-id", sessionID)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(msgBytes)
	return
}

// Callback works with sign-in callbacks
func Callback(w http.ResponseWriter, r *http.Request) {

	// Get session ID from request
	sessionID := r.URL.Query().Get("sessionId")

	// get JWZ token params from the post request
	tokenBytes, err := io.ReadAll(r.Body)

	// check if there is an error
	if err != nil {
		log.Printf("Server.callback() error reading request body, err: %v", err)
		return
	}

	// get authRequest from userSessionTracker.Get() by passing the sId
	authRequest, wasFound := userSessionTracker.Get(sessionID)
	if !wasFound { // If auth request not found for the session  ID
		fmt.Printf("auth request was not found for session ID: %s\n", sessionID)
		return
	}

	// Add Polygon Mumbai RPC node endpoint - needed to read on-chain state
	ethURL := "https://polygon-mumbai.g.alchemy.com/v2/vxZ13gzWqTPzjEAvZEQdHjmcV1620Gy8"

	// Add identity state contract address
	contractAddress := "0x134B1BE34911E39A8397ec6289782989729807a4"

	resolverPrefix := "polygon:mumbai"

	// Locate the directory that contains circuit's verification keys
	keyDIR := "./keys"

	// //fetch authRequest from sessionID
	// authRequest = requestMap[sessionID]

	// print authRequest
	// fmt.Println("Auth request: ", authRequest)

	// load the verification key
	var verificationKeyloader = &loaders.FSKeyLoader{Dir: keyDIR}
	resolver := state.ETHResolver{
		RPCUrl:          ethURL,
		ContractAddress: common.HexToAddress(contractAddress),
	}

	resolvers := map[string]pubsignals.StateResolver{
		resolverPrefix: resolver,
	}

	// EXECUTE VERIFICATION
	verifier, err := auth.NewVerifier(verificationKeyloader, resolvers, auth.WithIPFSGateway("https://ipfs.io"))
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	authResponse, err := verifier.FullVerify(
		context.Background(),
		string(tokenBytes),
		authRequest.(protocol.AuthorizationRequestMessage),
		pubsignals.WithAcceptedStateTransitionDelay(time.Minute*5))
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// make "m" map with key as string and value as an interface
	m := make(map[string]interface{})
	m["id"] = authResponse.From

	// messageBytes := []byte("User with ID " + +" Successfully authenticated")

	mBytes, _ := json.Marshal(m)
	fmt.Println("Successfully authenticated")
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(mBytes)

	userSessionTracker.Set(sessionID, m, cache.DefaultExpiration)

	return
}

// Get Request Status
func GetRequestStatus(w http.ResponseWriter, r *http.Request) {

	// Get Id from the http request
	id := r.URL.Query().Get("id")

	//check if the request ID is empty
	if id == "" {
		log.Println("Server.getRequestStatus() url parameter has invalid values")
		EncodeResponse(w, http.StatusBadRequest, fmt.Errorf("url parameter has invalid values"))
		return
	}

	// Get response bytes from getRequestStatus function while passing ID
	resB, err := getRequestStatus(id)

	// check if there is any error
	if err != nil {
		log.Printf("Server -> issuer.CommHandler.GetRequestStatus() return err, err: %v", err)
		EncodeResponse(w, http.StatusInternalServerError, fmt.Sprintf("can't get request status. err: %v", err))
		return
	}

	// check if response bytes is nill.
	if resB == nil {
		EncodeResponse(w, http.StatusNotFound, fmt.Errorf("can't get request status with id: %s", id))
		return
	}

	// call encode byte response function and pass http.ResponseWriter, http status and response bytes
	EncodeByteResponse(w, http.StatusOK, resB)
}

func getRequestStatus(id string) ([]byte, error) {
	log.Println("Communication.Callback() invoked")

	item, ok := userSessionTracker.Get(id)
	if !ok {
		log.Printf("item not found %v", id)
		return nil, nil
	}

	switch item.(type) {
	case protocol.AuthorizationRequestMessage:
		log.Println("no authorization response yet - no data available for this request")
		return nil, nil
	case map[string]interface{}:
		b, err := json.Marshal(item)
		if err != nil {
			return nil, fmt.Errorf("error marshalizing response: %v", err)
		}
		return b, nil
	}

	return nil, fmt.Errorf("unknown item return from tracker (type %T)", item)
}

func EncodeByteResponse(w http.ResponseWriter, statusCode int, res []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, err := w.Write(res)
	if err != nil {
		log.Panicln(err)
	}
}

func EncodeResponse(w http.ResponseWriter, statusCode int, res interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := codec.NewEncoder(w, &jsonHandle).Encode(res); err != nil {
		log.Println(err)
	}
}
