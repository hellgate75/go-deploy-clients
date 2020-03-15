// sshclient implements an ssh client
package client

import (
	"bytes"
	"errors"
	"fmt"
	depio "github.com/hellgate75/go-tcp-common/io"
	"github.com/hellgate75/go-deploy/net/generic"
	"github.com/hellgate75/go-tcp-client/common"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"net"
	"os"
)

type sshScriptType byte
type sshShellType byte

const (
	cmdLine sshScriptType = iota
	rawScript
	scriptFile

	interactiveShell sshShellType = iota
	nonInteractiveShell
)

type sshTranfer struct {
	client *ssh.Client
	stdout io.Writer
	stderr io.Writer
}

func (ts *sshTranfer) SetStdio(stdout, stderr io.Writer) generic.FileTransfer {
	ts.stdout = stdout
	ts.stderr = stderr
	return ts
}

func (ts *sshTranfer) MkDir(path string) error {
	return ts.MkDirAs(path, 0644)
}

func (ts *sshTranfer) MkDirAs(path string, mode os.FileMode) error {
	var globalError error = nil
	session, err := ts.client.NewSession()
	if err != nil {
		return errors.New("FileTransfer.MkDir: " + err.Error())
	}
	writer, _ := session.StdinPipe()
	defer func() {
		if r := recover(); r != nil {
			globalError = errors.New("FileTransfer.MkDir: " + fmt.Sprintf("%v", r))
		}
		if writer != nil {
			writer.Close()
		}
		if session != nil {
			session.Close()
		}
	}()
	mkDir(path, writer, mode)
	return globalError
}

func (ts *sshTranfer) TransferFile(path string, remotePath string) error {
	return ts.TransferFileAs(path, remotePath, 0644)
}

func (ts *sshTranfer) TransferFileAs(path string, remotePath string, mode os.FileMode) error {
	var globalError error = nil
	session, err := ts.client.NewSession()
	if err != nil {
		return errors.New("FileTransfer.TransferFile: " + err.Error())
	}
	writer, _ := session.StdinPipe()
	defer func() {
		if r := recover(); r != nil {
			globalError = errors.New("FileTransfer.TransferFile" + fmt.Sprintf("%v", r))
		}
		if writer != nil {
			writer.Close()
		}
		if session != nil {
			session.Close()
		}
	}()
	file, errF := os.Open(path)
	if errF != nil {
		return errors.New("FileTransfer.TransferFile::OpenFile: " + errF.Error())
	}
	content, errR := ioutil.ReadAll(file)
	if errR != nil {
		return errors.New("FileTransfer.TransferFile::ReadFile: " + errR.Error())
	}
	copyFile(content, remotePath, writer, mode)
	return globalError
}

func (ts *sshTranfer) TransferFolder(path string, remotePath string) error {
	return ts.TransferFolderAs(path, remotePath, 0644)
}

func (ts *sshTranfer) TransferFolderAs(path string, remotePath string, mode os.FileMode) error {
	var globalError error = nil
	session, err := ts.client.NewSession()
	if err != nil {
		return errors.New("FileTransfer.TransferFolder: " + err.Error())
	}
	writer, _ := session.StdinPipe()
	defer func() {
		if r := recover(); r != nil {
			globalError = errors.New("FileTransfer.TransferFolder" + fmt.Sprintf("%v", r))
		}
		if writer != nil {
			writer.Close()
		}
		if session != nil {
			session.Close()
		}
	}()
	stat, errS := os.Stat(path)
	if errS != nil {
		return errors.New("FileTransfer.TransferFolder::StatFile: " + errS.Error())
	}
	if !stat.IsDir() {
		return ts.TransferFileAs(path, remotePath, mode)
	}
	executeFunc(path, remotePath, writer, mode)
	return globalError
}

func executeFunc(path string, remotePath string, writer io.WriteCloser, mode os.FileMode) {
	stat, errS := os.Stat(path)
	if errS != nil {
		panic(errS)
	}
	if stat.IsDir() {
		mkDir(remotePath, writer, mode)
		files, err := ioutil.ReadDir(".")
		if err != nil {
			panic(err)
		}
		for _, f := range files {
			var fName = path + depio.GetPathSeparator() + f.Name()
			var fRemoteName = remotePath + "/" + f.Name()
			executeFunc(fName, fRemoteName, writer, f.Mode())
		}
	} else {
		file, errF := os.Open(path)
		if errF != nil {
			panic(errF.Error())
		}
		content, errR := ioutil.ReadAll(file)
		if errR != nil {
			panic(errR.Error())
		}
		copyFile(content, remotePath, writer, mode)
	}

}

func mkDir(path string, writer io.WriteCloser, mode os.FileMode) {
	fmt.Fprintln(writer, "D"+mode.String(), 0, path) // mkdir
}

func copyFile(content []byte, path string, writer io.WriteCloser, mode os.FileMode) {
	fmt.Fprintln(writer, "C"+mode.String(), len(content), path) // copyfile
	writer.Write(content)
	fmt.Fprint(writer, "\x00")
}

type sshScript struct {
	client     *ssh.Client
	_type      sshScriptType
	script     *bytes.Buffer
	scriptFile string
	err        error

	stdout io.Writer
	stderr io.Writer
}

// Execute
func (rs *sshScript) execute() error {
	if rs.err != nil {
		return errors.New("SSHScript.execute: " + rs.err.Error())
	}
	if rs._type == cmdLine {
		return rs.runCmds()
	} else if rs._type == rawScript {
		return rs.runScript()
	} else if rs._type == scriptFile {
		return rs.runScriptFile()
	} else {
		return errors.New(fmt.Sprintf("SSHScript.execute: Not supported execution type: %v", rs._type))
	}
}

func (rs *sshScript) ExecuteWithOutput() ([]byte, error) {
	if rs.stdout != nil {
		return nil, errors.New("SSHScript.ExecuteWithOutput: Stdout already set")
	}
	var out bytes.Buffer
	rs.stdout = &out
	err := rs.execute()
	if err != nil {
		err = errors.New("SSHScript.ExecuteWithFullOutput: " + err.Error())
	}
	return out.Bytes(), err
}

func (rs *sshScript) ExecuteWithFullOutput() ([]byte, error) {
	if rs.stdout != nil {
		return nil, errors.New("SSHScript.ExecuteWithFullOutput: Stdout already set")
	}
	if rs.stderr != nil {
		return nil, errors.New("SSHScript.ExecuteWithFullOutput: Stderr already set")
	}

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	rs.stdout = &stdout
	rs.stderr = &stderr
	err := rs.execute()
	if err != nil {
		return stderr.Bytes(), errors.New("SSHScript.ExecuteWithFullOutput: " + err.Error())
	}
	return stdout.Bytes(), err
}

func (rs *sshScript) NewCmd(cmd string) generic.CommandsScript {
	_, err := rs.script.WriteString(cmd + "\n")
	if err != nil {
		rs.err = errors.New("SSHScript.NewCmd: " + err.Error())
	}
	return rs
}

func (rs *sshScript) SetStdio(stdout, stderr io.Writer) generic.CommandsScript {
	rs.stdout = stdout
	rs.stderr = stderr
	return rs
}

func (rs *sshScript) runCmd(cmd string) error {
	session, err := rs.client.NewSession()
	if err != nil {
		return errors.New("SSHScript.runCmd: " + err.Error())
	}
	defer session.Close()

	session.Stdout = rs.stdout
	session.Stderr = rs.stderr

	if err := session.Run(cmd); err != nil {
		return errors.New("SSHScript.runCmd: " + err.Error())
	}
	return nil
}

func (rs *sshScript) runCmds() error {
	for {
		statment, err := rs.script.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("SSHScript.runCmds: " + err.Error())
		}

		if err := rs.runCmd(statment); err != nil {
			return errors.New("SSHScript.runCmds: " + err.Error())
		}
	}

	return nil
}

func (rs *sshScript) runScript() error {
	session, err := rs.client.NewSession()
	if err != nil {
		return err
	}

	session.Stdin = rs.script
	session.Stdout = rs.stdout
	session.Stderr = rs.stderr

	if err := session.Shell(); err != nil {
		return errors.New("SSHScript.runScript: " + err.Error())
	}
	if err := session.Wait(); err != nil {
		return errors.New("SSHScript.runScript: " + err.Error())
	}

	return nil
}

func (rs *sshScript) runScriptFile() error {
	var buffer bytes.Buffer
	file, err := os.Open(rs.scriptFile)
	if err != nil {
		return err
	}
	_, err = io.Copy(&buffer, file)
	if err != nil {
		return errors.New("SSHScript.runScriptFile: " + err.Error())
	}

	rs.script = &buffer
	err = rs.runScript()
	rs.script = bytes.NewBufferString("")
	if err != nil {
		errors.New("SSHScript.runScriptFile: " + err.Error())
	}
	return nil
}

type sshShell struct {
	client         *ssh.Client
	requestPty     bool
	terminalConfig *generic.TerminalConfig

	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (rs *sshShell) SetStdio(stdin io.Reader, stdout, stderr io.Writer) generic.RemoteShell {
	rs.stdin = stdin
	rs.stdout = stdout
	rs.stderr = stderr
	return rs
}

func (rs *sshShell) Close() error {
	return nil
}

func (rs *sshShell) Start() error {
	session, err := rs.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	if rs.stdin == nil {
		session.Stdin = os.Stdin
	} else {
		session.Stdin = rs.stdin
	}
	if rs.stdout == nil {
		session.Stdout = os.Stdout
	} else {
		session.Stdout = rs.stdout
	}
	if rs.stderr == nil {
		session.Stderr = os.Stderr
	} else {
		session.Stderr = rs.stderr
	}

	if rs.requestPty {
		tc := rs.terminalConfig
		if tc == nil {
			tc = &generic.TerminalConfig{
				Term:   "xterm",
				Height: 40,
				Weight: 80,
				Modes:  make(map[uint8]uint32),
			}
			tc.Modes[ssh.ECHO]=0 // Disable echoing
			tc.Modes[ssh.IGNCR]=1 // Ignore CR on input.]
		}
		if err := session.RequestPty(tc.Term, tc.Height, tc.Weight, tc.Modes); err != nil {
			return errors.New("SSHShell.Start: " + err.Error())
		}
	}

	if err := session.Shell(); err != nil {
		return errors.New("SSHShell.Start: " + err.Error())
	}

	if err := session.Wait(); err != nil {
		return errors.New("SSHShell.Start: " + err.Error())
	}

	return nil
}

type sshClient struct {
	client *ssh.Client
}

func (c *sshClient) Close() error {
	return c.client.Close()
}

func (c *sshClient) Clone() generic.NetworkClient {
	return &sshClient{
		client: c.client,
	}
}

func (c *sshClient) Terminal(config *generic.TerminalConfig) generic.RemoteShell {
	return &sshShell{
		client:         c.client,
		terminalConfig: config,
		requestPty:     true,
	}
}

func (c *sshClient) NewCmd(cmd string) generic.CommandsScript {
	return &sshScript{
		_type:  cmdLine,
		client: c.client,
		script: bytes.NewBufferString(cmd + "\n"),
	}
}

func (c *sshClient) Script(script string) generic.CommandsScript {
	return &sshScript{
		_type:  rawScript,
		client: c.client,
		script: bytes.NewBufferString(script + "\n"),
	}
}

func (c *sshClient) ScriptFile(fname string) generic.CommandsScript {
	return &sshScript{
		_type:      scriptFile,
		client:     c.client,
		scriptFile: fname,
	}
}

func (c *sshClient) FileTranfer() generic.FileTransfer {
	return &sshTranfer{
		client: c.client,
	}
}

func (c *sshClient) Shell() generic.RemoteShell {
	return &sshShell{
		client:     c.client,
		requestPty: false,
	}
}

type sshConnection struct {
	_client 	generic.NetworkClient
	Insecure	bool
}

func (conn *sshConnection) GetClient() generic.NetworkClient {
	return conn._client
}

func (conn *sshConnection) IsConnected() bool {
	return conn._client != nil
}

func (conn *sshConnection) Clone() generic.ConnectionHandler {
	if conn._client != nil {
		return &sshConnection{
			_client: conn._client.Clone(),
		}
	} else {
		return &sshConnection{
			_client: nil,
		}
	}
}

func (conn *sshConnection) Close() error {
	if !conn.IsConnected() {
		return errors.New("SSHConnectionHandler.Close: Not connected!!")
	}
	err := conn._client.Close()
	if err != nil {
		return errors.New("SSHConnectionHandler.Close: " + err.Error())
	}
	return nil
}

func (conn *sshConnection) ConnectWithPasswd(addr string, user string, passwd string) error {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(passwd),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return conn.Connect("tcp", addr, config)
}

func (conn *sshConnection) ConnectWithKey(addr string, user string, keyfile string) error {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return errors.New("SSHConnectionHandler.ConnectWithKey: " + err.Error())
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return errors.New("SSHConnectionHandler.ConnectWithKey: " + err.Error())
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return conn.Connect("tcp", addr, config)
}

func (conn *sshConnection) ConnectWithKeyAndPassphrase(addr string, user, keyfile string, passphrase string) error {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return errors.New("SSHConnectionHandler.ConnectWithKeyAndPassphrase: " + err.Error())
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	if err != nil {
		return errors.New("SSHConnectionHandler.ConnectWithKeyAndPassphrase: " + err.Error())
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return conn.Connect("tcp", addr, config)
}

func (conn *sshConnection) Connect(network, addr string, config *ssh.ClientConfig) error {
	client, err := ssh.Dial(network, addr, config)
	if err != nil {
		return errors.New("SSHConnectionHandler.Connect: " + err.Error())
	}
	conn._client = &sshClient{
		client: client,
	}
	return nil
}

func (conn *sshConnection) ConnectWithCertificate(addr string, port string, certificate common.CertificateKeyPair, caCert string) error {
	return errors.New("Authentication with PEM client certificte and key not allowed in SSH")
}

func (conn *sshConnection) UsePlugins(PluginLibraryExtension string, PluginLibrariesFolder string) {
	//INFO: No plugins available for default SSH Client
}

// NewSSHConnection: Creates a new SSH connection handler
func NewSSHConnection(insecure bool) generic.ConnectionHandler {
	return &sshConnection{
		_client: nil,
		Insecure: insecure,
	}
}

// NewSSHConnection: Creates a new SSH connection handler
func NewSingleSessionSSHConnection(insecure bool) generic.ConnectionHandler {
	return &sshConnection{
		_client: nil,
		Insecure: insecure,
	}
}
