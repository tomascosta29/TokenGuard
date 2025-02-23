// File: /home/fcosta/CostaAuth/./internal/model/token.go
package model

type Token struct {
	JTI   string `json:"jti"` // used for blacklisting
	Token string `json:"token"`
}
