package main

import (
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redhatinsights/mbop/internal/config"
	"github.com/redhatinsights/mbop/internal/handlers"
	l "github.com/redhatinsights/mbop/internal/logger"
	"github.com/redhatinsights/mbop/internal/middleware"
	"github.com/redhatinsights/mbop/internal/service/mailer"
	"github.com/redhatinsights/mbop/internal/store"
	"github.com/redhatinsights/platform-go-middlewares/v2/identity"
)

var conf = config.Get()

func main() {
	if err := l.Init(); err != nil {
		panic(err)
	}

	if err := store.SetupStore(); err != nil {
		panic(err)
	}

	mux := http.NewServeMux()

	withIdentity := func(h http.HandlerFunc) http.Handler {
		return identity.EnforceIdentity(h)
	}

	mux.HandleFunc("GET /{$}", handlers.Status)
	mux.HandleFunc("GET /v1/jwt", handlers.JWTV1Handler)
	mux.HandleFunc("POST /v1/users", handlers.UsersV1Handler)
	mux.HandleFunc("POST /v1/sendEmails", handlers.SendEmails)
	mux.HandleFunc("GET /v3/accounts/{orgID}/users", handlers.AccountsV3UsersHandler)
	mux.HandleFunc("POST /v3/accounts/{orgID}/usersBy", handlers.AccountsV3UsersByHandler)
	mux.HandleFunc("GET /v1/auth", handlers.AuthV1Handler)
	mux.HandleFunc("GET /api/entitlements/{rest...}", handlers.CatchAll)
	mux.HandleFunc("GET /{rest...}", handlers.CatchAll)
	mux.HandleFunc("POST /{rest...}", handlers.CatchAll)

	mux.Handle("GET /v1/registrations", withIdentity(handlers.RegistrationListHandler))
	mux.Handle("POST /v1/registrations", withIdentity(handlers.RegistrationCreateHandler))
	mux.Handle("DELETE /v1/registrations/{uid}", withIdentity(handlers.RegistrationDeleteHandler))
	mux.Handle("GET /v1/registrations/token", withIdentity(handlers.TokenHandler))
	mux.Handle("GET /api/mbop/v1/allowlist", withIdentity(handlers.AllowlistListHandler))
	mux.Handle("POST /api/mbop/v1/allowlist", withIdentity(handlers.AllowlistCreateHandler))
	mux.Handle("DELETE /api/mbop/v1/allowlist", withIdentity(handlers.AllowlistDeleteHandler))

	r := middleware.Logging(mux)

	err := mailer.InitConfig()
	if err != nil {
		// TODO: should we panic if the mailer module fails to init?
		l.Log.Info("failed to init mailer module", "error", err)
	}

	// listen for OS signals so we can terminate when receiving one
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)

	go func() {
		srv := http.Server{
			Addr:              ":" + conf.Port,
			ReadHeaderTimeout: 2 * time.Second,
			Handler:           r,
		}

		l.Log.Info("Starting MBOP HTTP Listener", "port", conf.Port)
		if err := srv.ListenAndServe(); err != nil {
			l.Log.Error(err, "server couldn't start")
		}
	}()

	if conf.UseTLS {
		go func() {
			srv := http.Server{
				Addr:              ":" + conf.TLSPort,
				ReadHeaderTimeout: 2 * time.Second,
				Handler:           r,
			}

			l.Log.Info("Starting MBOP HTTPS Listener", "port", conf.TLSPort)
			if err := srv.ListenAndServeTLS(conf.CertDir+"/tls.crt", conf.CertDir+"/tls.key"); err != nil {
				l.Log.Error(err, "server couldn't start")
			}
		}()
	}

	<-interrupts
}
