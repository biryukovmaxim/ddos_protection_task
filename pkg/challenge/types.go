package challenge

type RequestType = uint8

const (
	RequestChallengeType RequestType = iota
	SendChallengeType
	SolutionType
	ConfirmationType
)

const (
	ChallengeSize = 8
	Difficulty    = 22
)

type Solution struct {
	Hash  []byte
	Nonce uint64
}

type VerificationResponse struct {
	bool
}
