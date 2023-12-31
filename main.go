package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"server/proof"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/rs/cors"

	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/iden3/iden3comm/v2/protocol"
)

func main() {

	mux := http.NewServeMux()

	mux.HandleFunc("/api/sign-in", GetAuthRequest)
	mux.HandleFunc("/api/callback", Callback)
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	handler := cors.Default().Handler(mux)

	http.ListenAndServe(":8080", handler)

	// http.HandleFunc("/api/sign-in", GetAuthRequest)
	// http.HandleFunc("/api/callback", Callback)
	// http.Handle("/", http.FileServer(http.Dir("./static")))
	// http.ListenAndServe(":8080", nil)
}

// Create a map to store the auth requests and their session IDs
var requestMap = make(map[string]interface{})

func GetAuthRequest(w http.ResponseWriter, r *http.Request) {

	// Audience is verifier id
	rURL := "https://702c-112-134-215-182.ngrok-free.app"
	sessionID := 1
	CallbackURL := "/api/callback"
	Audience := "did:polygonid:polygon:mumbai:2qG7bhdJKsk4tSbShiXiF2Eti2cVjUH3iTDXyyn6i7"

	uri := fmt.Sprintf("%s%s?sessionId=%s", rURL, CallbackURL, strconv.Itoa(sessionID))

	// Generate request for basic authentication
	var request protocol.AuthorizationRequestMessage = auth.CreateAuthorizationRequest("test flow", Audience, uri)

	request.ID = "7f38a193-0918-4a48-9fac-36adfdb8b542"
	request.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542"

	// Add request for a specific proof
	mtpProofRequest := proof.ProofRequest()
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	// Store auth request in map associated with session ID
	requestMap[strconv.Itoa(sessionID)] = request

	// print request
	fmt.Println(request)

	msgBytes, _ := json.Marshal(request)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(msgBytes)
	return
}

// Callback works with sign-in callbacks
func Callback(w http.ResponseWriter, r *http.Request) {

	// Get session ID from request
	sessionID := r.URL.Query().Get("sessionId")

	// get JWZ token params from the post request
	tokenBytes, _ := io.ReadAll(r.Body)

	// Add Polygon Mumbai RPC node endpoint - needed to read on-chain state
	ethURL := "https://polygon-mumbai.g.alchemy.com/v2/vxZ13gzWqTPzjEAvZEQdHjmcV1620Gy8"

	// Add identity state contract address
	contractAddress := "0x134B1BE34911E39A8397ec6289782989729807a4"

	resolverPrefix := "polygon:mumbai"

	// Locate the directory that contains circuit's verification keys
	keyDIR := "./keys"

	// fetch authRequest from sessionID
	authRequest := requestMap[sessionID]

	// print authRequest
	fmt.Println("Auth request: ", authRequest)

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
		r.Context(),
		string(tokenBytes),
		authRequest.(protocol.AuthorizationRequestMessage),
		pubsignals.WithAcceptedStateTransitionDelay(time.Minute*5))
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userID := authResponse.From

	messageBytes := []byte("User with ID " + userID + " Successfully authenticated")
	fmt.Println("Successfully authenticated")
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(messageBytes)

	return
}
