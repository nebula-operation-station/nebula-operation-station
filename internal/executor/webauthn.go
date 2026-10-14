// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// LegacyCredentialsFile is the Milestone 0 credential file. LoadCredentials
// imports it into executor.db once and renames it.
const LegacyCredentialsFile = "webauthn-credentials.json"

// LoadCredentials returns the WebAuthn credentials registered in db. A
// legacy webauthn-credentials.json in dataDir is imported first (IDs that
// already exist are skipped) and then renamed to *.imported, so that a
// credential removed later cannot come back from the file.
func LoadCredentials(db *executordb.DB, dataDir string, log *slog.Logger) ([]webauthnverify.Credential, error) {
	path := filepath.Join(dataDir, LegacyCredentialsFile)
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var legacy []webauthnverify.Credential
		if err := json.Unmarshal(b, &legacy); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		imported := 0
		for _, c := range legacy {
			err := db.AddWebAuthnCredential(executordb.WebAuthnCredential{
				ID: c.ID, PublicKey: c.PublicKey, UserHandle: c.UserHandle, UserName: "admin", Label: c.Label,
				CreatedBy: "import:" + LegacyCredentialsFile, SignCount: c.SignCount,
			})
			switch {
			case errors.Is(err, executordb.ErrCredentialExists):
			case err != nil:
				return nil, fmt.Errorf("import %s: %w", path, err)
			default:
				imported++
			}
		}
		if err := os.Rename(path, path+".imported"); err != nil {
			return nil, err
		}
		log.Info("audit", "kind", "credentials_imported", "file", path, "imported", imported, "renamed_to", path+".imported")
	}

	list, err := db.ListWebAuthnCredentials()
	if err != nil {
		return nil, err
	}
	out := make([]webauthnverify.Credential, 0, len(list))
	for _, c := range list {
		out = append(out, webauthnverify.Credential{ID: c.ID, PublicKey: c.PublicKey, UserHandle: c.UserHandle, Label: c.Label})
	}
	return out, nil
}

// RegistrationAuditLogger returns a webauthnreg audit hook that writes
// structured log lines.
func RegistrationAuditLogger(log *slog.Logger) func(webauthnreg.Event) {
	return func(e webauthnreg.Event) {
		log.Info("audit", "kind", e.Kind, "credential", e.Credential, "by", e.By, "detail", e.Detail)
	}
}

func (s *Service) CreateRegistrationCode(ctx context.Context, req *pb.CreateRegistrationCodeRequest) (*pb.CreateRegistrationCodeResponse, error) {
	code, exp, err := s.reg.CreateCode(req.GetUserName(), req.GetLabel(), callerName(ctx))
	if err != nil {
		return nil, regStatus(err)
	}
	return &pb.CreateRegistrationCodeResponse{Code: code, ExpiryUnix: exp.Unix()}, nil
}

func (s *Service) BeginRegistration(_ context.Context, req *pb.BeginRegistrationRequest) (*pb.BeginRegistrationResponse, error) {
	b, err := s.reg.Begin(req.GetCode())
	if err != nil {
		return nil, regStatus(err)
	}
	return &pb.BeginRegistrationResponse{
		RegistrationId:           b.ID,
		CreationOptionsJson:      b.CreationOptions,
		AuthorizationOptionsJson: b.AuthorizationOptions,
		ExpiryUnix:               b.Expiry.Unix(),
	}, nil
}

func (s *Service) FinishRegistration(_ context.Context, req *pb.FinishRegistrationRequest) (*pb.FinishRegistrationResponse, error) {
	res, err := s.reg.Finish(req.GetRegistrationId(), req.GetAttestationJson(), req.GetAssertionJson())
	if err != nil {
		return nil, regStatus(err)
	}
	// A new credential ends a pending recovery (spec 05).
	if _, pending, err := s.db.RecoveryPending(); err == nil && pending {
		if err := s.db.ClearRecoveryPending(); err != nil {
			s.log.Error("audit", "kind", "store_error", "op", "clear_recovery_pending", "detail", err.Error())
		} else {
			s.log.Warn("audit", "kind", "recovery_completed", "credential", hex.EncodeToString(res.CredentialID))
		}
	}
	return &pb.FinishRegistrationResponse{
		CredentialId: base64.RawURLEncoding.EncodeToString(res.CredentialID),
		Label:        res.Label,
	}, nil
}

func (s *Service) ListWebAuthnCredentials(_ context.Context, _ *pb.ListWebAuthnCredentialsRequest) (*pb.ListWebAuthnCredentialsResponse, error) {
	list, err := s.db.ListWebAuthnCredentials()
	if err != nil {
		return nil, s.adminStoreError("list_webauthn_credentials", err)
	}
	out := &pb.ListWebAuthnCredentialsResponse{}
	for _, c := range list {
		out.Credentials = append(out.Credentials, &pb.WebAuthnCredential{
			CredentialId: base64.RawURLEncoding.EncodeToString(c.ID), UserName: c.UserName, Label: c.Label,
			Aaguid: hex.EncodeToString(c.AAGUID), AttestationFormat: c.AttestationFormat,
			CreatedAtUnix: c.CreatedAt.Unix(), CreatedBy: c.CreatedBy,
		})
	}
	return out, nil
}

func (s *Service) RemoveWebAuthnCredential(ctx context.Context, req *pb.RemoveWebAuthnCredentialRequest) (*pb.RemoveWebAuthnCredentialResponse, error) {
	id, err := base64.RawURLEncoding.DecodeString(req.GetCredentialId())
	if err != nil || len(id) == 0 {
		return nil, status.Error(codes.InvalidArgument, "credential_id must be base64url")
	}
	who := callerName(ctx)
	removed, err := s.reg.Remove(id)
	if removed {
		// A credential is removed because it may be lost or compromised:
		// whatever it approved or opened goes too.
		s.auth.Lock(who)
		s.log.Info("audit", "kind", "credential_removed", "by", who, "credential", hex.EncodeToString(id))
	}
	if err != nil {
		if errors.Is(err, webauthnreg.ErrRemovalNotStored) {
			s.log.Error("audit", "kind", "credential_removal_not_stored", "by", who, "credential", hex.EncodeToString(id),
				"detail", err.Error())
		}
		return nil, s.adminStoreError("remove_webauthn_credential", err)
	}
	return &pb.RemoveWebAuthnCredentialResponse{Removed: removed}, nil
}

// BeginLogin starts a web login (M2).
func (s *Service) BeginLogin(_ context.Context, _ *pb.BeginLoginRequest) (*pb.BeginLoginResponse, error) {
	l, err := s.reg.BeginLogin()
	if err != nil {
		return nil, regStatus(err)
	}
	return &pb.BeginLoginResponse{LoginId: l.ID, RequestOptionsJson: l.OptionsJSON, ExpiryUnix: l.Expiry.Unix()}, nil
}

// FinishLogin verifies a web login assertion and names the credential.
func (s *Service) FinishLogin(ctx context.Context, req *pb.FinishLoginRequest) (*pb.FinishLoginResponse, error) {
	id, err := s.reg.FinishLogin(req.GetLoginId(), req.GetAssertionJson())
	if err != nil {
		s.log.Warn("audit", "kind", "login_failed", "by", callerName(ctx), "code", string(webauthnreg.CodeOf(err)))
		return nil, regStatus(err)
	}
	resp := &pb.FinishLoginResponse{CredentialId: base64.RawURLEncoding.EncodeToString(id)}
	if list, err := s.db.ListWebAuthnCredentials(); err == nil {
		for _, c := range list {
			if bytes.Equal(c.ID, id) {
				resp.UserName, resp.Label = c.UserName, c.Label
			}
		}
	}
	s.log.Info("audit", "kind", "login_succeeded", "by", callerName(ctx), "credential", hex.EncodeToString(id), "user", resp.UserName)
	return resp, nil
}

// CheckCredential reports whether a credential is still registered (M2-6).
func (s *Service) CheckCredential(_ context.Context, req *pb.CheckCredentialRequest) (*pb.CheckCredentialResponse, error) {
	if req.GetCredentialId() == RecoveryCredentialID {
		t, err := s.db.GetTOTP()
		return &pb.CheckCredentialResponse{Registered: err == nil && t.Activated}, nil
	}
	id, err := base64.RawURLEncoding.DecodeString(req.GetCredentialId())
	if err != nil || len(id) == 0 || len(id) > 1023 {
		return nil, status.Error(codes.InvalidArgument, "credential_id must be base64url")
	}
	return &pb.CheckCredentialResponse{Registered: s.reg.HasCredential(id)}, nil
}

func regStatus(err error) error {
	var c codes.Code
	switch webauthnreg.CodeOf(err) {
	case webauthnreg.CodeInvalidRequest:
		c = codes.InvalidArgument
	case webauthnreg.CodeCodeInvalid:
		c = codes.Unauthenticated
	case webauthnreg.CodeNotFound:
		c = codes.NotFound
	case webauthnreg.CodeExpired, webauthnreg.CodeNotAllowed:
		c = codes.FailedPrecondition
	case webauthnreg.CodeAttestation, webauthnreg.CodeAssertion:
		c = codes.PermissionDenied
	case webauthnreg.CodeExists:
		c = codes.AlreadyExists
	case webauthnreg.CodeLimit, webauthnreg.CodeLoginLimit:
		c = codes.ResourceExhausted
	case webauthnreg.CodeNoCredentials:
		c = codes.FailedPrecondition
	case webauthnreg.CodeLoginNotFound:
		c = codes.NotFound
	case webauthnreg.CodeLoginRejected:
		c = codes.Unauthenticated
	case webauthnreg.CodeStorage:
		c = codes.Unavailable
	default:
		return status.Error(codes.Internal, "registration failed")
	}
	return status.Error(c, err.Error())
}
