package handlers

import (
	"net/http"
	"time"

	"github.com/redhatinsights/mbop/internal/config"
	"github.com/redhatinsights/mbop/internal/models"
	"github.com/redhatinsights/platform-go-middlewares/v2/identity"
)

type TokenResp struct {
	Token string `json:"token"`
}

func TokenHandler(w http.ResponseWriter, r *http.Request) {
	xrhid := identity.Get(r.Context()).Identity
	if !xrhid.User.OrgAdmin {
		doError(w, "user must be org admin to obtain satellite token", 403)
		return
	}

	if xrhid.OrgID == "" {
		do400(w, "Missing org_id in x-rh-identity")
		return
	}

	if xrhid.User.Username == "" {
		do400(w, "Missing username in x-rh-identity")
		return
	}

	c := config.Get()
	privateKey := []byte(c.PrivateKey)
	pubKey := []byte(c.PublicKey)

	token := models.Token{PrivateKey: privateKey, PublicKey: pubKey}
	ttl, err := time.ParseDuration(c.TokenTTL)
	if err != nil {
		do500(w, "Error setting TTL")
		return
	}

	signedToken, err := token.Create(ttl, xrhid)
	if err != nil {
		do500(w, "Error creating token")
		return
	}

	sendJSON(w, TokenResp{Token: signedToken})
}
