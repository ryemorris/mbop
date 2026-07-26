package handlers

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	l "github.com/redhatinsights/mbop/internal/logger"
	"github.com/redhatinsights/mbop/internal/store"
	"github.com/redhatinsights/platform-go-middlewares/v2/identity"
)

type allowlistCreateRequest struct {
	IPBlock string `json:"ip_block"`
}

type allowListResponse struct {
	IPBlock   string    `json:"ip_block"`
	OrgID     string    `json:"org_id"`
	CreatedAt time.Time `json:"created_at"`
}

func AllowlistCreateHandler(w http.ResponseWriter, r *http.Request) {
	id := identity.Get(r.Context())
	if !id.Identity.User.OrgAdmin {
		doError(w, "user must be org admin to add addresses to allowlist", 403)
		return
	}

	var createReq allowlistCreateRequest
	err := json.NewDecoder(r.Body).Decode(&createReq)
	if err != nil {
		do400(w, "invalid json in body - only expected key is [ip]")
		return
	}

	if !strings.Contains(createReq.IPBlock, "/") {
		createReq.IPBlock += "/32"
	}

	_, _, err = net.ParseCIDR(createReq.IPBlock)
	if err != nil {
		do400(w, "invalid IP block, needs to be an IPv4 range or single IP")
		return
	}

	db := store.GetStore()

	err = db.AllowAddress(&store.AllowlistBlock{IPBlock: createReq.IPBlock, OrgID: id.Identity.OrgID})
	if err != nil {
		do500(w, "error storing address: "+err.Error())
		return
	}

	w.WriteHeader(201)
}

func AllowlistDeleteHandler(w http.ResponseWriter, r *http.Request) {
	id := identity.Get(r.Context())
	if !id.Identity.User.OrgAdmin {
		doError(w, "user must be org admin to add addresses to allowlist", 403)
		return
	}

	block := r.URL.Query().Get("block")
	if block == "" {
		do400(w, "need address in path in the form `/api/v1/allowlist?block={block}")
		return
	}

	db := store.GetStore()

	err := db.DenyAddress(&store.AllowlistBlock{IPBlock: block, OrgID: id.Identity.OrgID})
	if err != nil {
		if errors.Is(err, store.ErrAddressNotAllowListed) {
			doError(w, "ip not allowlisted", 404)
			return
		}

		do500(w, "error deleting addressaddress: %w"+err.Error())
		return
	}

	w.WriteHeader(204)
}

func AllowlistListHandler(w http.ResponseWriter, r *http.Request) {
	id := identity.Get(r.Context())
	if !id.Identity.User.OrgAdmin {
		doError(w, "user must be org admin to add addresses to allowlist", 403)
		return
	}

	db := store.GetStore()

	addrs, err := db.AllowedAddresses(id.Identity.OrgID)
	if err != nil {
		do500(w, "error listing addresses: %w"+err.Error())
		return
	}

	out := make([]allowListResponse, len(addrs))
	for i, addr := range addrs {
		out[i] = allowListResponse{
			IPBlock:   addr.IPBlock,
			OrgID:     addr.OrgID,
			CreatedAt: addr.CreatedAt,
		}
	}

	err = json.NewEncoder(w).Encode(out)
	if err != nil {
		l.Log.Info("failed to encode response", "error", err)
	}
}
