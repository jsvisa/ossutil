package lib

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"

	_ "crypto/sha256"

	_ "golang.org/x/crypto/ripemd160"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const rsaBits = 4096

func decodePrivateKey(filename string) *packet.PrivateKey {
	// open ascii armored private key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening private key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PrivateKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid private key"), "Error parsing private key")
	}
	return key
}

func decodePublicKey(filename string) *packet.PublicKey {
	// open ascii armored public key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PublicKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid public key"), "Error parsing public key")
	}
	return key
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: rsaBits,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365 * 10)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}

func encryptFile(pubKey *packet.PublicKey, privKey *packet.PrivateKey, filePath string) (io.Reader, error) {
	to := createEntityFromKeys(pubKey, privKey)

	buf := new(bytes.Buffer)
	encoderWriter, err := armor.Encode(buf, "Message", make(map[string]string))
	if err != nil {
		return nil, fmt.Errorf("Error createing OpenPGP armor: %v", err)
	}

	plain, err := openpgp.Encrypt(encoderWriter, []*openpgp.Entity{to}, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error createing OpenPGP entity: %v", err)
	}

	compressed, err := gzip.NewWriterLevel(plain, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	fd, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	io.Copy(compressed, fd)
	compressed.Close()
	plain.Close()
	encoderWriter.Close()

	return bytes.NewReader(buf.Bytes()), err
}

func decryptFile(pubKey *packet.PublicKey, privKey *packet.PrivateKey, body io.ReadCloser) (io.Reader, error) {
	entity := createEntityFromKeys(pubKey, privKey)

	block, err := armor.Decode(body)
	kingpin.FatalIfError(err, "Error reading OpenPGP Armor: %s", err)

	if block.Type != "Message" {
		return nil, fmt.Errorf("Invalid message type")
	}

	var entityList openpgp.EntityList
	entityList = append(entityList, entity)

	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error reading message: %v", err)
	}

	compressed, err := gzip.NewReader(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("Invalid compression level: %v", err)
	}
	defer compressed.Close()

	return compressed, err
}
