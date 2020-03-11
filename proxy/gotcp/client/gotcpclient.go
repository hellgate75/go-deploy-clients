package client

import (
	"bytes"
	"errors"
	"fmt"
	depio "github.com/hellgate75/go-tcp-common/io"
	"github.com/hellgate75/go-deploy/net/generic"
	"github.com/hellgate75/go-tcp-client/client/proxy"
	"github.com/hellgate75/go-tcp-client/client/worker"
	"github.com/hellgate75/go-tcp-client/common"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"os"
	"time"
)

type goTcpScriptType byte
type goTcpShellType byte

const (
	cmdLine goTcpScriptType = iota
	rawScript
	scriptFile

	interactiveShell goTcpShellType = iota
	nonInteractiveShell
)

type goTcpTranfer struct {
	client common.TCPClient
	stdout io.Writer
	stderr io.Writer
	_singleSession bool
}

func (ts *goTcpTranfer) SetStdio(stdout, stderr io.Writer) generic.FileTransfer {
	ts.stdout = stdout
	ts.stderr = stderr
	return ts
}

func (ts *goTcpTranfer) MkDir(path string) error {
	return ts.MkDirAs(path, 0644)
}

func (ts *goTcpTranfer) MkDirAs(path string, mode os.FileMode) error {
	err := mkDir(ts._singleSession, path, ts.client, mode, ts.stdout, ts.stderr)
	return err
}

func (ts *goTcpTranfer) TransferFile(path string, remotePath string) error {
	return ts.TransferFileAs(path, remotePath, 0644)
}

func (ts *goTcpTranfer) TransferFileAs(path string, remotePath string, mode os.FileMode) error {
	stat, errS := os.Stat(path)
	if errS != nil {
		return errors.New("GoTcpTransfer.TransferFileAs::StatFile: " + errS.Error())
	}
	if stat.IsDir() {
		return ts.TransferFolderAs(path, remotePath, mode)
	}
	err := copyFile(ts._singleSession, path, remotePath, ts.client, mode, ts.stdout, ts.stderr)
	if err != nil {
		return err
	}
	return nil
}

func (ts *goTcpTranfer) TransferFolder(path string, remotePath string) error {
	return ts.TransferFolderAs(path, remotePath, 0644)
}

func (ts *goTcpTranfer) TransferFolderAs(path string, remotePath string, mode os.FileMode) error {
	stat, errS := os.Stat(path)
	if errS != nil {
		return errors.New("GoTcpTransfer.TransferFolder::StatFile: " + errS.Error())
	}
	if !stat.IsDir() {
		return ts.TransferFileAs(path, remotePath, mode)
	}
	err := executeFunc(ts._singleSession, path, remotePath, ts.client, mode, ts.stdout, ts.stderr)
	if err != nil {
		return err
	}
	return nil
}

func executeFunc(singleSession bool,path string, remotePath string, client common.TCPClient, mode os.FileMode, stdout io.Writer, stderr io.Writer) error {
	stat, errS := os.Stat(path)
	if errS != nil {
		return errS
	}
	if stat.IsDir() {
		mkDir(singleSession, remotePath, client, mode, stdout, stderr)
		files, err := ioutil.ReadDir(path)
		if err != nil {
			return err
		}
		for _, f := range files {
			var fName = path + depio.GetPathSeparator() + f.Name()
			var fRemoteName = remotePath + "/" + f.Name()
			err := executeFunc(singleSession, fName, fRemoteName, client, f.Mode(), stdout, stderr)
			if err != nil {
				return err
			}
		}
	} else {
		err := copyFile(singleSession, path, remotePath, client, mode, stdout, stderr)
		if err != nil {
			return err
		}
	}
	return nil
}

func mkDir(singleSession bool, remotePath string, client common.TCPClient, mode os.FileMode, stdout io.Writer, stderr io.Writer) error {
	if ! singleSession {
		defer func() {
			client.SendText("exit")
			client.Close()
		}()
		err := client.Open(false)
		if err != nil {
			return err
		}
	}
	err := client.ApplyCommand("transfer-file", "folder", remotePath, mode.String())
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	resp, errR := client.ReadAnswer()
	if errR != nil {
		return errR
	}
	if len(resp) >= 2 {
		if resp[0:2] == "ko" {
			if len(resp) > 3 {
				if stderr != nil {
					stderr.Write([]byte(resp[3:]))
				}
				return errors.New("TCPScript.runCmd: " + resp[3:])
			} else {
				if stderr != nil {
					stderr.Write([]byte(resp))
				}
				return errors.New("TCPScript.runCmd: Undefined error from server")
			}
		} else if resp[0:2] == "ok" {
			if stdout != nil {
				stdout.Write([]byte(resp))
			}
		} else {
			if len(resp) > 3 {
				if stdout != nil {
					stdout.Write([]byte(resp[3:]))
				}
			} else {
				if stdout != nil {
					stdout.Write([]byte(resp))
				}
			}

		}
	} else {
		if stdout != nil {
			stdout.Write([]byte(resp))
		}
	}
	return nil
}

func copyFile(singleSession bool, localPath string, remotePath string, client common.TCPClient, mode os.FileMode, stdout io.Writer, stderr io.Writer) error {
	if ! singleSession {
		defer func() {
			client.SendText("exit")
			client.Close()
		}()
		err := client.Open(false)
		if err != nil {
			return err
		}

	}
	err := client.ApplyCommand("transfer-file", localPath, remotePath, mode.String())
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	resp, errR := client.ReadAnswer()
	if errR != nil {
		return errR
	}
	if len(resp) >= 2 {
		if resp[0:2] == "ko" {
			if len(resp) > 3 {
				if stderr != nil {
					stderr.Write([]byte(resp[3:]))
				}
				return errors.New("TCPScript.runCmd: " + resp[3:])
			} else {
				if stderr != nil {
					stderr.Write([]byte(resp))
				}
				return errors.New("TCPScript.runCmd: Undefined error from server")
			}
		} else if resp[0:2] == "ok" {
			if stdout != nil {
				stdout.Write([]byte(resp))
			}
		} else {
			if len(resp) > 3 {
				if stdout != nil {
					stdout.Write([]byte(resp[3:]))
				}
			} else {
				if stdout != nil {
					stdout.Write([]byte(resp))
				}
			}

		}
	} else {
		if stdout != nil {
			stdout.Write([]byte(resp))
		}
	}
	return nil
}

type goTcpScript struct {
	client     common.TCPClient
	_type      goTcpScriptType
	script     *bytes.Buffer
	scriptFile string
	err        error
	_singleSession bool

	stdout io.Writer
	stderr io.Writer
}

// Execute
func (rs *goTcpScript) execute() error {
	if rs.err != nil {
		return errors.New("GoTCPScript.execute: " + rs.err.Error())
	}
	if rs._type == cmdLine {
		return rs.runCmds()
	} else if rs._type == rawScript {
		return rs.runScript()
	} else if rs._type == scriptFile {
		return rs.runScriptFile()
	} else {
		return errors.New(fmt.Sprintf("GoTCPScript.execute: Not supported execution type: %v", rs._type))
	}
}

func (rs *goTcpScript) ExecuteWithOutput() ([]byte, error) {
	if rs.stdout != nil {
		return nil, errors.New("GoTCPScript.ExecuteWithOutput: Stdout already set")
	}
	var out bytes.Buffer
	rs.stdout = &out
	err := rs.execute()
	if err != nil {
		err = errors.New("GoTCPScript.ExecuteWithOutput: " + err.Error())
	}
	return out.Bytes(), err
}

func (rs *goTcpScript) ExecuteWithFullOutput() ([]byte, error) {
	if rs.stdout != nil {
		return nil, errors.New("GoTCPScript.ExecuteWithFullOutput: Stdout already set")
	}
	if rs.stderr != nil {
		return nil, errors.New("GoTCPScript.ExecuteWithFullOutput: Stderr already set")
	}

	var (
		stdout *bytes.Buffer = bytes.NewBuffer([]byte{})
		stderr *bytes.Buffer = bytes.NewBuffer([]byte{})
	)
	rs.stdout = stdout
	rs.stderr = stderr
	err := rs.execute()
	if err != nil {
		return stderr.Bytes(), errors.New("GoTCPScript.ExecuteWithFullOutput: " + err.Error())
	}
	return stdout.Bytes(), nil
}

func (rs *goTcpScript) NewCmd(cmd string) generic.CommandsScript {
	_, err := rs.script.WriteString(cmd + "\n")
	if err != nil {
		rs.err = errors.New("GoTCPScript.NewCmd: " + err.Error())
	}
	return rs
}

func (rs *goTcpScript) SetStdio(stdout, stderr io.Writer) generic.CommandsScript {
	rs.stdout = stdout
	rs.stderr = stderr
	return rs
}

func (rs *goTcpScript) runCmd(cmd string) error {
	if ! rs._singleSession {
		defer func() {
			rs.client.Close()
		}()
		err := rs.client.Open(false)
		if err != nil {
			return err
		}
	}
	err := rs.client.ApplyCommand("shell", "false", cmd, nil, rs.stdout, rs.stderr)
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	resp, errR := rs.client.ReadAnswer()
	if errR != nil {
		return errR
	}
	if len(resp) >= 2 {
		if resp[0:2] == "ko" {
			if len(resp) > 3 {
				if rs.stderr != nil {
					rs.stderr.Write([]byte(resp[3:]))
				}
				return errors.New("GoTCPScript.runCmd: " + resp[3:])
			} else {
				if rs.stderr != nil {
					rs.stderr.Write([]byte(resp))
				}
				return errors.New("GoTCPScript.runCmd: Undefined error from server")
			}
		} else if resp[0:2] == "ok" {
			if rs.stdout != nil {
				rs.stdout.Write([]byte(resp))
			}
		} else {
			if len(resp) > 3 {
				if rs.stdout != nil {
					rs.stdout.Write([]byte(resp[3:]))
				}
			} else {
				if rs.stdout != nil {
					rs.stdout.Write([]byte(resp))
				}
			}

		}
	} else {
//		if rs.stdout != nil {
//			rs.stdout.Write([]byte(resp))
//		}
	}
	return nil
}

func (rs *goTcpScript) runCmds() error {
	for {
		statment, err := rs.script.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("GoTCPScript.runCmds: " + err.Error())
		}

		if err := rs.runCmd(statment); err != nil {
			return errors.New("GoTCPScript.runCmds: " + err.Error())
		}
	}

	return nil
}

func (rs *goTcpScript) runScript() error {
	if ! rs._singleSession {
		defer func() {
			rs.client.Close()
		}()
		err := rs.client.Open(false)
		if err != nil {
			return err
		}
	}
	err := rs.client.ApplyCommand("shell", "false", string(rs.script.Bytes()), nil, rs.stdout, rs.stderr)
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	resp, errR := rs.client.ReadAnswer()
	if errR != nil {
		return errR
	}
	if len(resp) >= 2 {
		if resp[0:2] == "ko" {
			if len(resp) > 3 {
				if rs.stderr != nil {
					rs.stderr.Write([]byte(resp[3:]))
				}
				return errors.New("GoTCPScript.runScript: " + resp[3:])
			} else {
				if rs.stderr != nil {
					rs.stderr.Write([]byte(resp))
				}
				return errors.New("GoTCPScript.runScript: Undefined error from server")
			}
		} else if resp[0:2] == "ok" {
			//if rs.stdout != nil {
			//	rs.stdout.Write([]byte(resp))
			//}
		} else {
			if len(resp) > 3 {
				if rs.stdout != nil {
					rs.stdout.Write([]byte(resp[3:]))
				}
			} else {
				if rs.stdout != nil {
					rs.stdout.Write([]byte(resp))
				}
			}

		}
	} else {
//		if rs.stdout != nil {
//			rs.stdout.Write([]byte(resp))
//		}
	}
	return nil
}

func (rs *goTcpScript) runScriptFile() error {
	if ! rs._singleSession {
		defer func() {
			rs.client.Close()
		}()
		err := rs.client.Open(false)
		if err != nil {
			return err
		}
	}
	err := rs.client.ApplyCommand("shell", "false", rs.scriptFile)
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	resp, errR := rs.client.ReadAnswer()
	if errR != nil {
		return errR
	}
	if len(resp) >= 2 {
		if resp[0:2] == "ko" {
			if len(resp) > 3 {
				if rs.stderr != nil {
					rs.stderr.Write([]byte(resp[3:]))
				}
				return errors.New("GoTCPScript.runScript: " + resp[3:])
			} else {
				if rs.stderr != nil {
					rs.stderr.Write([]byte(resp))
				}
				return errors.New("GoTCPScript.runScript: Undefined error from server")
			}
		} else if resp[0:2] == "ok" {
			//if rs.stdout != nil {
			//	rs.stdout.Write([]byte(resp))
			//}
		} else {
			if len(resp) > 3 {
				if rs.stdout != nil {
					rs.stdout.Write([]byte(resp[3:]))
				}
			} else {
				if rs.stdout != nil {
					rs.stdout.Write([]byte(resp))
				}
			}

		}
	} else {
		//if rs.stdout != nil {
		//	rs.stdout.Write([]byte(resp))
		//}
	}
	return nil
}

type goTcpShell struct {
	client         common.TCPClient
	requestPty     bool
	terminalConfig *generic.TerminalConfig
	_singleSession bool

	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (rs *goTcpShell) SetStdio(stdin io.Reader, stdout, stderr io.Writer) generic.RemoteShell {
	rs.stdin = stdin
	rs.stdout = stdout
	rs.stderr = stderr
	return rs
}

func (rs *goTcpShell) Close() error {
	if rs.stdin == nil || rs.stdout == nil || rs.stderr == nil {
		return errors.New("GoTcpShell:Close() -> Shell not open for miss of stdout, stderr, stdin")
	}
	if ! rs._singleSession {
		rs.client.Close()
	}

	return nil
}

func (rs *goTcpShell) Start() error {
	if rs.stdin == nil || rs.stdout == nil || rs.stderr == nil {
		return errors.New("GoTcpShell:Start() -> Please provide stdout, stderr, stdin for the shell execution")
	}
	if ! rs._singleSession {
		rs.client.Open(false)
	}
	err := rs.client.ApplyCommand("shell", "true", "", rs.stdin, rs.stdout, rs.stderr)
	if err != nil {
		return errors.New("GoTcpShell:Start() -> Details: " + err.Error())
	}
	return nil
}

type goTcpClient struct {
	client common.TCPClient
	_singleSession bool
}

func (conn *goTcpClient) Clone() generic.NetworkClient {
	if conn.client != nil {
		if conn._singleSession {
			return &goTcpClient{
				client: conn.client,
				_singleSession: conn._singleSession,
			}
		} else {
			return &goTcpClient{
				client: conn.client.Clone(),
				_singleSession: conn._singleSession,
			}
		}
	} else {
		return &goTcpClient{
			client: nil,
		}
	}
}

func (c *goTcpClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	} else {
		return errors.New("Unable to clone empty client, please open client first ...")
	}
}

func (c *goTcpClient) Terminal(config *generic.TerminalConfig) generic.RemoteShell {
	if c.client == nil {
		return nil
	}
	if c._singleSession {
		return &goTcpShell{
			client:         c.client,
			terminalConfig: config,
			requestPty:     true,
			_singleSession: c._singleSession,
		}
	}
	return &goTcpShell{
		client:         c.client.Clone(),
		terminalConfig: config,
		requestPty:     true,
		_singleSession: c._singleSession,
	}
}

func (c *goTcpClient) NewCmd(cmd string) generic.CommandsScript {
	if c.client == nil {
		return nil
	}
	if c._singleSession {
		return &goTcpScript{
			_type:  cmdLine,
			client: c.client,
			script: bytes.NewBufferString(cmd + "\n"),
			_singleSession: c._singleSession,
		}
	}
	return &goTcpScript{
		_type:  cmdLine,
		client: c.client.Clone(),
		script: bytes.NewBufferString(cmd + "\n"),
		_singleSession: c._singleSession,
	}
}

func (c *goTcpClient) Script(script string) generic.CommandsScript {
	if c.client == nil {
		return nil
	}
	if c._singleSession {
		return &goTcpScript{
			_type:  rawScript,
			client: c.client,
			script: bytes.NewBufferString(script + "\n"),
			_singleSession: c._singleSession,
		}
	}
	return &goTcpScript{
		_type:  rawScript,
		client: c.client.Clone(),
		script: bytes.NewBufferString(script + "\n"),
		_singleSession: c._singleSession,
	}
}

func (c *goTcpClient) ScriptFile(fname string) generic.CommandsScript {
	if c.client == nil {
		return nil
	}
	if c._singleSession {
		return &goTcpScript{
			_type:      scriptFile,
			client:     c.client,
			scriptFile: fname,
			_singleSession: c._singleSession,
		}
	}
	return &goTcpScript{
		_type:      scriptFile,
		client:     c.client.Clone(),
		scriptFile: fname,
		_singleSession: c._singleSession,
	}
}

func (c *goTcpClient) FileTranfer() generic.FileTransfer {
	if c.client == nil {
		return nil
	}
	if c._singleSession {
		return &goTcpTranfer{
			client: c.client,
			_singleSession: c._singleSession,
		}
	}
	return &goTcpTranfer{
		client: c.client.Clone(),
		_singleSession: c._singleSession,
	}
}

func (c *goTcpClient) Shell() generic.RemoteShell {
	if c.client == nil {
		return nil
	}
	if c._singleSession {
		return &goTcpShell{
			client:     c.client,
			requestPty: false,
			_singleSession: c._singleSession,
		}
	}
	return &goTcpShell{
		client:     c.client.Clone(),
		requestPty: false,
		_singleSession: c._singleSession,
	}
}

type goTcpConnection struct {
	_client generic.NetworkClient
	_singleSession bool
}

func (conn *goTcpConnection) GetClient() generic.NetworkClient {
	return conn._client
}

func (conn *goTcpConnection) IsConnected() bool {
	return conn._client != nil
}

func (conn *goTcpConnection) Clone() generic.ConnectionHandler {
	if conn._client != nil {
		return &goTcpConnection{
			_client: conn._client.Clone(),
			_singleSession: conn._singleSession,
		}
	} else {
		return &goTcpConnection{
			_client: nil,
			_singleSession: conn._singleSession,
		}
	}
}

func (conn *goTcpConnection) Close() error {
	if !conn.IsConnected() {
		return errors.New("SSHConnectionHandler.Close: Not connected!!")
	}
	err := conn._client.Close()
	if err != nil {
		return errors.New("SSHConnectionHandler.Close: " + err.Error())
	}
	return nil
}

func (conn *goTcpConnection) ConnectWithPasswd(addr string, user string, passwd string) error {
	return errors.New("User/password connection not allowed to Go TCP Server")
}

func (conn *goTcpConnection) ConnectWithKey(addr string, user string, keyfile string) error {
	return errors.New("User/rsa key connection not allowed to Go TCP Server")
}

func (conn *goTcpConnection) ConnectWithKeyAndPassphrase(addr string, user, keyfile string, passphrase string) error {
	return errors.New("User/rsa key connection not allowed to Go TCP Server")
}

func (conn *goTcpConnection) Connect(network, addr string, config *ssh.ClientConfig) error {
	return errors.New("User/rsa key connection not allowed to Go TCP Server")
}

func (conn *goTcpConnection) UsePlugins(PluginLibraryExtension string, PluginLibrariesFolder string) {
	if ! proxy.UsePlugins {
		proxy.UsePlugins = true
		proxy.PluginLibrariesExtension = PluginLibraryExtension
		proxy.PluginLibrariesFolder = PluginLibrariesFolder
	}
}


func (conn *goTcpConnection) ConnectWithCertificate(addr string, port string, certificate common.CertificateKeyPair, caCert string) error {
	client := worker.NewClient(certificate, caCert, addr, port)
	if conn._singleSession {
		client.Open(false)
	}
	conn._client = &goTcpClient{
		client: client,
		_singleSession: conn._singleSession,
	}
	return nil
}

// NewSSHConnection: Creates a new SSH connection handler
func NewGoTCPConnection() generic.ConnectionHandler {
	return &goTcpConnection{
		_client: nil,
		_singleSession: false,
	}
}

// NewSSHConnection: Creates a new SSH connection handler
func NewSingleSessionGoTCPConnection() generic.ConnectionHandler {
	return &goTcpConnection{
		_client: nil,
		_singleSession: true,
	}
}
