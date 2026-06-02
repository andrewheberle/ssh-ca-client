package userconfig

type UserConfig struct {
	Certificate  []byte `json:"certificate,omitempty"`
	RefreshToken []byte `json:"refresh_token,omitempty"`
	PrivateKey   []byte `json:"private_key,omitempty"`
}
