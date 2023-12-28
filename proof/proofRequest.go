package proof

import (
	circuits "github.com/iden3/go-circuits/v2"
	"github.com/iden3/iden3comm/v2/protocol"
)

func ProofRequest() protocol.ZeroKnowledgeProofRequest {

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"birthday": map[string]interface{}{
				"$lt": 20000101,
			},
		},
		"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		"type":    "KYCAgeCredential",
	}

	return mtpProofRequest
}
