// Command api is the PatchProof AI HTTP API entrypoint.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/patchproof/patchproof-go/internal/api"
	"github.com/patchproof/patchproof-go/internal/config"
	"github.com/patchproof/patchproof-go/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("patchproof-api: %s", err)
	}
}

func run() error {
	config.LoadDotEnv()
	settings := config.FromEnv()
	st := store.FromSettings(settings)
	if err := st.InitDB(); err != nil {
		return err
	}
	if n, err := st.FailStaleScans(); err != nil {
		log.Printf("stale-scan recovery failed: %s", err)
	} else if n > 0 {
		log.Printf("marked %d interrupted scan(s) as failed", n)
	}

	addr := fmt.Sprintf("%s:%d", settings.Host, settings.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: api.NewServer(st, settings).Handler(),
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("listening on %s", ln.Addr())

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %s", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	signal.Stop(stop)
	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return err
	}
	<-done
	return nil
}
