package models

type User struct {
	GUID         string
	RefreshToken string
	IpHash       string
	Email        string
}
