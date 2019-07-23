package main

import (
	"database/sql"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"time"
)

var Mysql *sql.DB

func CheckError(errMasg error) {
	if errMasg != nil {
		panic(errMasg)
	}
}

func Connect(user, password, host, key string, port int) (*ssh.Client, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		config       ssh.Config
		//session      *ssh.Session
		err error
	)

	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	if key == "" {
		auth = append(auth, ssh.Password(password))
	} else {
		pemBytes, err := ioutil.ReadFile(key)
		if err != nil {
			return nil, err
		}

		var signer ssh.Signer
		if password == "" {
			signer, err = ssh.ParsePrivateKey(pemBytes)
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(password))
		}
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	clientConfig = &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 30 * time.Second,
		Config:  config,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	addr = fmt.Sprintf("%s:%d", host, port)

	client, err = ssh.Dial("tcp", addr, clientConfig)
	return client, err
}

func main() {
	fmt.Println("main start")
	const (
		username = "root"
		password = ""
		ip       = "39.104.226.149"
		port     = 22
		key      = "/Users/hikaruamano/.ssh/id_rsa"
		dbUser   = "root"           // DB username
		dbPass   = "root"           // DB Password
		dbHost   = "127.0.0.1:3306" // DB Hostname/IP
		dbName   = "spider"         // Database name
	)
	var err error

	sshClient, err := Connect(username, password, ip, key, port)
	mysql.RegisterDial("mytcpchannel", func(addr string) (net.Conn, error) {
		return sshClient.Dial("tcp", addr)
	})

	Mysql, err = sql.Open("mysql", fmt.Sprintf("%s:%s@mytcpchannel(%s)/%s", dbUser, dbPass, dbHost, dbName))
	CheckError(err)

	testQuery()

}

func testQuery() {

	rows, err := Mysql.Query("SELECT * FROM oss  LIMIT 1")
	CheckError(err)

	column, _ := rows.Columns()
	values := make([][]byte, len(column))
	scans := make([]interface{}, len(column))
	for i := range values {
		scans[i] = &values[i]
	}
	results := make(map[int]map[string]string)
	i := 0
	for rows.Next() {
		if err := rows.Scan(scans...); err != nil {
			fmt.Println(err)
			return
		}
		row := make(map[string]string)
		for k, v := range values {
			key := column[k]
			row[key] = string(v)
		}
		results[i] = row
		i++
	}

	fmt.Println("results", results)
}
