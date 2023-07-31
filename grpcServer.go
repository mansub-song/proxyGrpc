package proxyGrpc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	// pb "SAC24/proxyGrpc"

	"github.com/SherLzp/goRecrypt/curve"
	"github.com/SherLzp/goRecrypt/recrypt"
	"github.com/fentec-project/gofe/abe"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const port = 50051

var priKey *ecdsa.PrivateKey
var pubKey *ecdsa.PublicKey
var famePubKey *abe.FAMEPubKey
var fameSecKey *abe.FAMESecKey
var fame *abe.FAME

// server is used to implement reapGRPC.GreeterServer.
type server struct {
	UnimplementedGreeterServer
}

// Get preferred outbound ip of this machine
func GetLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// client <-> proxy
func (s *server) GetAttributeKeyCipher(ctx context.Context, in *ClientSendRequest) (*ClientReceiveReply, error) {
	cid := in.GetCid()
	attributeSet := in.GetAttributeSet()
	pubKey := in.GetPubKey()

	//TODO: levelDB 읽어서 ip찾기

	// data owner와 연결
	ip := "147.46.240.242"
	conn, err := grpc.Dial(ip+":"+strconv.Itoa(port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := NewGreeterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	//data owner와 rpc 통신
	dataOwnerReply, err := c.GetReEncryptionKey(ctx, &ProxyNodeSendRequest{attributeSet: attributeSet, pubKey: pubKey})
	if err != nil {
		log.Fatalf("Failed to GetReEncryptionKey rpc function: %v", err)
	}
	//
	reEncKey := dataOwnerReply.GetRereEncKey()

	reEncPubKey := dataOwnerReply.GetReEncPubKey()
	cipherText := dataOwnerReply.GetCipherText()
	capsuleString := dataOwnerReply.GetCapsule()

	//데이터 변환
	rk := new(big.Int)
	rk, _ = rk.SetString(reEncKey)
	var capsule *recrypt.Capsule
	err = json.Unmarshal([]byte(capsuleString), &capsule)
	if err != nil {
		log.Fatalf("Failed to Unmarshal: %v", err)
	}
	//re-encrypt
	newCapsule, err := recrypt.ReEncryption(rk, capsule)
	if err != nil {
		log.Fatalf("Failed to ReEncryption: %v", err)
	}

	newCapsuleBytes, _ := json.Marshal(newCapsule)
	return &ClientReceiveReply{newCapsule: string(newCapsuleBytes), reEncPubKey: reEncPubKey, cipherText: cipherText}, nil
	// log.Printf("Greeting: %s", r.GetMessage())
}

// proxy <-> data owner
func (s *server) GetReEncryptionKey(ctx context.Context, in *ProxyNodeSendRequest) (*ProxyNodeReceiveReply, error) {
	attributeSet := in.GetAttributeSet()
	attrSet := strings.Split(attributeSet, " ")

	clientPubKey := in.GetClientPubKey()

	//attribute key 생성
	attributeKey, err := fame.GenerateAttribKeys(attrSet, fameSecKey)
	if err != nil {
		log.Fatalf("Failed to GenerateAttribKeys: %v", err)
	}
	//attribute key Encryption
	attributeKeyBytes, err := json.Marshal(attributeKey)
	cipherText, capsule, err := recrypt.Encrypt(string(attributeKeyBytes), pubKey)
	if err != nil {
		log.Fatalf("Failed to Encrypt: %v", err)
	}
	//re-encryption key gen
	rk, pubX, err := recrypt.ReKeyGen(priKey, clientPubKey)
	if err != nil {
		log.Fatalf("Failed to ReKeyGen: %v", err)
	}

	pubXBytes, _ := json.Marshal(pubX)
	capsuleBytes, _ := json.Marshal(capsule)
	return &ProxyNodeReceiveReply{reEncKey: rk.String(), reEncPubKey: string(pubXBytes), cipherText: string(cipherText), capsule: string(capsuleBytes)}, nil //이부분 string으로 변환
}

func ServerInit() {
	localIP := GetLocalIP().String()
	lis, err := net.Listen("tcp", fmt.Sprintf(localIP+":%d", port))
	if err != nil {
		fmt.Printf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &server{})
	fmt.Printf("grpc server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		fmt.Printf("failed to serve: %v", err)
	}

	priKey, pubKey, _ = curve.GenerateKeys()
	fame = abe.NewFAME()
	famePubKey, fameSecKey, err = fame.GenerateMasterKeys()
	if err != nil {
		log.Fatalf("Failed to generate master keys: %v", err)
	}

}
