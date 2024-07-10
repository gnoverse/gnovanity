package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/pprof"

	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/gnolang/gno/tm2/pkg/crypto/bip39"
	"github.com/gnolang/gno/tm2/pkg/crypto/hd"
	keysclient "github.com/gnolang/gno/tm2/pkg/crypto/keys/client"
	"github.com/gnolang/gno/tm2/pkg/crypto/secp256k1"
)

func main() {
	patternString := flag.String("pattern", "^g100", "regexp to filter results")
	threads := flag.Int("threads", runtime.GOMAXPROCS(0), "number of threads")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to `file`")
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close() // error handling omitted for example
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		pprof.StopCPUProfile()
		os.Exit(1)
	}()

	pattern := regexp.MustCompile(*patternString)

	for i := 0; i < *threads; i++ {
		go runLoop(pattern)
	}

	select {}
}

func runLoop(pattern *regexp.Regexp) {
	for {
		mnemonic, err := keysclient.GenerateMnemonic(256)
		if err != nil {
			panic("unable to generate mnemonic: " + err.Error())
		}
		result, err := generateKey(mnemonic, "", 0, 0)
		if err != nil {
			panic("unable to generate key: " + err.Error())
		}
		addr := result.Address()
		if pattern.MatchString(addr.String()) {
			fmt.Printf("ADDRESS:  %s\n", addr.String())
			fmt.Printf("MNEMONIC: %s\n", mnemonic)
		}
	}
}

func generateKey(mnemonic, passwd string, account, index uint32) (crypto.PubKey, error) {
	coinType := crypto.CoinType
	hdPath := hd.NewFundraiserParams(account, coinType, index)

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passwd)
	if err != nil {
		return nil, err
	}

	masterPriv, ch := hd.ComputeMastersFromSeed(seed)
	derivedPriv, err := hd.DerivePrivateKeyForPath(masterPriv, ch, hdPath.String())
	if err != nil {
		return nil, err
	}
	priv := secp256k1.PrivKeySecp256k1(derivedPriv)

	// encrypt private key using passphrase
	pub := priv.PubKey()
	return pub, nil
}
