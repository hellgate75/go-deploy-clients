package gotcp

import (
	"github.com/hellgate75/go-deploy/net/generic"
	"github.com/hellgate75/go-deploy-clients/proxy/gotcp/client"
)

func NewGoTCPConnectionHandler(singleSession bool) generic.ConnectionHandler {
	if singleSession {
		return client.NewSingleSessionGoTCPConnection()

	}
	return client.NewGoTCPConnection()
}
