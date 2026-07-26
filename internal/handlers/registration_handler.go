package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/redhatinsights/mbop/internal/config"
	"github.com/redhatinsights/mbop/internal/store"
	"github.com/redhatinsights/platform-go-middlewares/v2/identity"
)

type registationCreateRequest struct {
	UID         *string `json:"uid,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
}

type registrationCollection struct {
	Registrations []registrationResponse `json:"registrations"`
	Meta          registrationMeta       `json:"meta"`
}

type registrationResponse struct {
	UID         string    `json:"uid"`
	DisplayName string    `json:"display_name"`
	Username    string    `json:"username"`
	CreatedAt   time.Time `json:"created_at"`
}

type registrationMeta struct {
	Count int `json:"count"`
}

func RegistrationListHandler(w http.ResponseWriter, r *http.Request) {
	id := identity.Get(r.Context())
	if !id.Identity.User.OrgAdmin {
		doError(w, "user must be org admin to list registrations", 403)
		return
	}

	limit, err := getLimit(r)
	if err != nil {
		do400(w, err.Error())
		return
	}
	offset, err := getOffset(r)
	if err != nil {
		do400(w, err.Error())
		return
	}

	db := store.GetStore()
	regs, count, err := db.All(id.Identity.OrgID, limit, offset)
	if err != nil {
		do500(w, err.Error())
		return
	}

	out := make([]registrationResponse, len(regs))
	for i := range regs {
		out[i] = registrationResponse{
			UID:         regs[i].UID,
			DisplayName: regs[i].DisplayName,
			Username:    regs[i].Username,
			CreatedAt:   regs[i].CreatedAt,
		}
	}

	sendJSON(w, &registrationCollection{
		Registrations: out,
		Meta: registrationMeta{
			Count: count,
		},
	})
}

func RegistrationCreateHandler(w http.ResponseWriter, r *http.Request) {
	id := identity.Get(r.Context())
	db := store.GetStore()

	if config.Get().AllowlistEnabled {
		allowed, err := db.AllowedIP(r.Header.Get(config.Get().AllowlistHeader), id.Identity.OrgID)
		if err != nil {
			do500(w, "error listing ip addresses: "+err.Error())
			return
		}
		if !allowed {
			doError(w, "address is not allowlisted", 403)
			return
		}
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		do500(w, "failed to read body bytes: "+err.Error())
		return
	}

	var body registationCreateRequest
	err = json.Unmarshal(b, &body)
	if err != nil {
		do400(w, "invalid body, need a json object with [uid] and [display_name] to register satellite")
		return
	}

	if body.UID == nil || *body.UID == "" {
		do400(w, "required parameter [uid] not found in body")
		return
	}

	if body.DisplayName == nil || *body.DisplayName == "" {
		do400(w, "required parameter [display_name] not found in body")
		return
	}

	if !id.Identity.User.OrgAdmin {
		doError(w, "user must be org admin to register satellite", 403)
		return
	}
	if id.Identity.User.Username == "" {
		do400(w, "[username] not present in identity header")
		return
	}

	gatewayCN, err := getCertCN(r.Header.Get(CertHeader))
	if err != nil {
		do400(w, err.Error())
		return
	}

	if gatewayCN != *body.UID {
		do400(w, "x-rh-certauth-cn does not match uid")
		return
	}

	_, err = db.Create(&store.Registration{
		OrgID:       id.Identity.OrgID,
		Username:    id.Identity.User.Username,
		UID:         *body.UID,
		DisplayName: *body.DisplayName,
	})
	if err != nil {
		if errors.Is(err, store.ErrRegistrationAlreadyExists{}) {
			doError(w, err.Error(), 409)
		} else {
			do500(w, "failed to create registration: "+err.Error())
		}
		return
	}

	sendJSONWithStatusCode(w, newResponse("Successfully registered"), 201)
}

func RegistrationDeleteHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if uid == "" {
		do400(w, "invalid uid passed in path")
	}

	id := identity.Get(r.Context())
	if !id.Identity.User.OrgAdmin {
		doError(w, "user must be org admin to register satellite", 403)
		return
	}

	db := store.GetStore()

	err := db.Delete(id.Identity.OrgID, uid)
	if err != nil {
		if errors.Is(err, store.ErrRegistrationNotFound) {
			do404(w, err.Error())
		} else {
			do500(w, "error deleting registration: "+err.Error())
		}
		return
	}

	w.WriteHeader(204)
}
