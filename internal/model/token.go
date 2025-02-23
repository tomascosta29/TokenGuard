package model

type Token struct {
	JTI   string `json:"jti"` // used for blacklisting
	Token string `json:"token"`
}
