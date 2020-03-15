package proxy

import (
	"errors"
	"github.com/hellgate75/go-deploy-clients/proxy/gotcp"
	"github.com/hellgate75/go-deploy-clients/proxy/ssh"
	"github.com/hellgate75/go-deploy/net/generic"
	"strings"
)


func newSshConnectionHandler(singleSession bool, insecure bool) (generic.ConnectionHandler, generic.ConnectionHandlerConfig) {
	return ssh.NewSshConnectionHandler(singleSession, insecure), generic.ConnectionHandlerConfig{
		UseAuthKey:             true,
		UseAuthKeyPassphrase:   true,
		UseSSHConfig:           true,
		UseUserPassword:        true,
		UseCertificates:        false,
	}
}

func newGoTCPConnectionHandler(singleSession bool, insecure bool) (generic.ConnectionHandler, generic.ConnectionHandlerConfig) {
	return gotcp.NewGoTCPConnectionHandler(singleSession, insecure), generic.ConnectionHandlerConfig{
		UseAuthKey:             false,
		UseAuthKeyPassphrase:   false,
		UseSSHConfig:           false,
		UseUserPassword:        false,
		UseCertificates:        true,
	}
}


func GetConnectionHandlerFactory(name string) (generic.NewConnectionHandlerFunc, error) {
	if strings.ToLower(name) == "ssh" {
		return newSshConnectionHandler, nil
	} else if strings.ToLower(name) == "go_deploy" {
		return newGoTCPConnectionHandler, nil
	}
	return nil, errors.New("Unable to discover '" + name + "' client!!")
}

func main(){

}