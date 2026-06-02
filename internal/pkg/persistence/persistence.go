package persistence

import "github.com/andrewheberle/ssh-ca-client/internal/pkg/userconfig"

type Persistence interface {
	Get() *userconfig.UserConfig
	Save() error
	Set(config *userconfig.UserConfig) error
}
