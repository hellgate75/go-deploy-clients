package ssh

import (
	"github.com/hellgate75/go-deploy/net/generic"
	"github.com/hellgate75/go-deploy-clients/proxy/ssh/client"
)

func NewSshConnectionHandler(singleSession bool, insecure bool) generic.ConnectionHandler {
	if singleSession {
		return client.NewSingleSessionSSHConnection(insecure)
	}
	return client.NewSSHConnection(insecure)
}
