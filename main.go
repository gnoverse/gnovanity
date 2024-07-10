// Command gnovanity helps you generate gno vnanity addresses
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
	"sync/atomic"
	"time"

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
	printStats := flag.Bool("print-stats", false, "print perf stats every 10s")
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

	if *printStats {
		for range time.Tick(time.Second * 10) {
			val := done.Swap(0)
			fmt.Fprintf(os.Stderr, "STATS: %d/sec\n", val/10)
		}
	} else {
		select {}
	}
}

var done atomic.Uint64

func runLoop(pattern *regexp.Regexp) {
	for {
		mnemonic, err := keysclient.GenerateMnemonic(256)
		if err != nil {
			panic("unable to generate mnemonic: " + err.Error())
		}
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
		if err != nil {
			panic("could not generate seed: " + err.Error())
		}
		for i := uint32(0); i < (1 << 20); i++ {
			result, err := generateKey(seed, 0, i)
			if err != nil {
				panic("unable to generate key: " + err.Error())
			}
			addr := result.Address()
			if pattern.MatchString(addr.String()) {
				fmt.Printf("ADDRESS:  %s\n", addr.String())
				fmt.Printf("PARAMS:   ACCOUNT:%7d INDEX:%7d\n", 0, i)
				fmt.Printf("MNEMONIC: %s\n", mnemonic)
			}
			done.Add(1)
		}
	}
}

type resultKey struct {
	pub            crypto.PubKey
	account, index uint32
}

func generateKey(seed []byte, account, index uint32) (crypto.PubKey, error) {
	coinType := crypto.CoinType
	hdPath := hd.NewFundraiserParams(account, coinType, index)

	masterPriv, ch := hd.ComputeMastersFromSeed(seed)
	derivedPriv, err := hd.DerivePrivateKeyForPath(masterPriv, ch, hdPath.String())
	if err != nil {
		return nil, err
	}
	priv := secp256k1.PrivKeySecp256k1(derivedPriv)

	pub := priv.PubKey()
	return pub, nil
}
