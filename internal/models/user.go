package models

type User struct {
	GUID               string
	RefreshToken       string
	CombinedTokensHash string
	IpHash             string
	Email              string
}
