// Copyright (c) 2026 Proton AG
//
// This file is part of Proton Mail Bridge.
//
// Proton Mail Bridge is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Proton Mail Bridge is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Proton Mail Bridge. If not, see <https://www.gnu.org/licenses/>.

// Package web provides an authenticated HTTP frontend for Bridge administration.
package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/proton-bridge/v3/internal/bridge"
	"github.com/ProtonMail/proton-bridge/v3/internal/constants"
	"github.com/ProtonMail/proton-bridge/v3/internal/events"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("pkg", "frontend/web") //nolint:gochecknoglobals

type Config struct {
	Address   string
	AdminUser string
	AdminPass string
}

type bridgeAPI interface {
	GetUserIDs() []string
	GetUserInfo(userID string) (bridge.UserInfo, error)
	LoginFull(
		ctx context.Context,
		username string,
		password []byte,
		getTOTP func() (string, error),
		getKeyPass func() ([]byte, error),
	) (string, error)
	LogoutUser(ctx context.Context, userID string) error
	DeleteUser(ctx context.Context, userID string) error
	SendBadEventUserFeedback(ctx context.Context, userID string, doResync bool) error
	GetIMAPPort() int
	SetIMAPPort(ctx context.Context, newPort int) error
	GetIMAPSSL() bool
	SetIMAPSSL(ctx context.Context, newSSL bool) error
	GetSMTPPort() int
	SetSMTPPort(ctx context.Context, newPort int) error
	GetSMTPSSL() bool
	SetSMTPSSL(ctx context.Context, newSSL bool) error
	Repair()
}

type Service struct {
	bridge  bridgeAPI
	eventCh <-chan events.Event
	quitCh  <-chan struct{}

	adminUser string
	adminPass string

	server *http.Server

	syncLock     sync.RWMutex
	userSyncInfo map[string]syncStatus
}

type syncStatus struct {
	State            string    `json:"state"`
	Progress         float64   `json:"progress"`
	ElapsedSeconds   float64   `json:"elapsedSeconds"`
	RemainingSeconds float64   `json:"remainingSeconds"`
	Error            string    `json:"error,omitempty"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type accountResponse struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	State       string     `json:"state"`
	Addresses   []string   `json:"addresses"`
	AddressMode string     `json:"addressMode"`
	Password    string     `json:"password"`
	UsedSpace   uint64     `json:"usedSpace"`
	MaxSpace    uint64     `json:"maxSpace"`
	Sync        syncStatus `json:"sync"`
}

type loginRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	TOTP            string `json:"totp,omitempty"`
	MailboxPassword string `json:"mailboxPassword,omitempty"`
}

type mailServerSettings struct {
	Host          string `json:"host"`
	IMAPPort      int    `json:"imapPort"`
	SMTPPort      int    `json:"smtpPort"`
	UseSSLForIMAP bool   `json:"useSSLForImap"`
	UseSSLForSMTP bool   `json:"useSSLForSmtp"`
}

func NewService(
	bridge *bridge.Bridge,
	eventCh <-chan events.Event,
	quitCh <-chan struct{},
	config Config,
) (*Service, error) {
	return newService(bridge, eventCh, quitCh, config)
}

func newService(
	bridge bridgeAPI,
	eventCh <-chan events.Event,
	quitCh <-chan struct{},
	config Config,
) (*Service, error) {
	if strings.TrimSpace(config.AdminUser) == "" {
		return nil, fmt.Errorf("missing web admin user; set --web-admin-user or BRIDGE_WEB_ADMIN_USER")
	}

	if strings.TrimSpace(config.AdminPass) == "" {
		return nil, fmt.Errorf("missing web admin password; set --web-admin-pass or BRIDGE_WEB_ADMIN_PASS")
	}

	if strings.TrimSpace(config.Address) == "" {
		config.Address = "127.0.0.1:8081"
	}

	if err := validateAddress(config.Address); err != nil {
		return nil, err
	}

	service := &Service{
		bridge:       bridge,
		eventCh:      eventCh,
		quitCh:       quitCh,
		adminUser:    config.AdminUser,
		adminPass:    config.AdminPass,
		userSyncInfo: make(map[string]syncStatus),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", service.handleIndex)
	mux.HandleFunc("/healthz", service.handleHealth)
	mux.Handle("/api/v1/accounts", service.withAuth(http.HandlerFunc(service.handleAccounts)))
	mux.Handle("/api/v1/accounts/", service.withAuth(http.HandlerFunc(service.handleAccountByID)))
	mux.Handle("/api/v1/server/mail", service.withAuth(http.HandlerFunc(service.handleMailSettings)))
	mux.Handle("/api/v1/repair", service.withAuth(http.HandlerFunc(service.handleRepair)))

	service.server = &http.Server{
		Addr:              config.Address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return service, nil
}

func (s *Service) Loop() error {
	log.WithField("address", s.server.Addr).Info("Starting web administration API")

	go s.watchEvents()

	doneCh := make(chan struct{})
	defer close(doneCh)

	go func() {
		select {
		case <-s.quitCh:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.server.Shutdown(ctx); err != nil {
				log.WithError(err).Error("Failed to stop web administration API")
			}
		case <-doneCh:
		}
	}()

	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to serve web administration API: %w", err)
	}

	log.Info("Web administration API stopped")
	return nil
}

func (s *Service) watchEvents() {
	for event := range s.eventCh {
		switch event := event.(type) {
		case events.SyncStarted:
			s.setSyncStatus(event.UserID, syncStatus{
				State:     "running",
				Progress:  0,
				UpdatedAt: time.Now().UTC(),
			})

		case events.SyncProgress:
			s.setSyncStatus(event.UserID, syncStatus{
				State:            "running",
				Progress:         event.Progress * 100,
				ElapsedSeconds:   event.Elapsed.Seconds(),
				RemainingSeconds: event.Remaining.Seconds(),
				UpdatedAt:        time.Now().UTC(),
			})

		case events.SyncFinished:
			s.setSyncStatus(event.UserID, syncStatus{
				State:            "finished",
				Progress:         100,
				ElapsedSeconds:   0,
				RemainingSeconds: 0,
				UpdatedAt:        time.Now().UTC(),
			})

		case events.SyncFailed:
			errMsg := ""
			if event.Error != nil {
				errMsg = event.Error.Error()
			}

			s.setSyncStatus(event.UserID, syncStatus{
				State:     "failed",
				Error:     errMsg,
				UpdatedAt: time.Now().UTC(),
			})
		}
	}
}

func (s *Service) setSyncStatus(userID string, status syncStatus) {
	s.syncLock.Lock()
	defer s.syncLock.Unlock()
	s.userSyncInfo[userID] = status
}

func (s *Service) getSyncStatus(userID string) syncStatus {
	s.syncLock.RLock()
	defer s.syncLock.RUnlock()

	if status, ok := s.userSyncInfo[userID]; ok {
		return status
	}

	return syncStatus{
		State:     "unknown",
		UpdatedAt: time.Now().UTC(),
	}
}

func (s *Service) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !s.validCredentials(user, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="bridge-admin"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Service) validCredentials(user, pass string) bool {
	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(s.adminUser)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(s.adminPass)) == 1
	return userMatch && passMatch
}

func (s *Service) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service": "Proton Mail Bridge web administration API",
		"version": "v1",
		"routes": []string{
			"GET /healthz",
			"GET /api/v1/accounts",
			"POST /api/v1/accounts",
			"GET /api/v1/accounts/{id}",
			"POST /api/v1/accounts/{id}/logout",
			"DELETE /api/v1/accounts/{id}",
			"POST /api/v1/accounts/{id}/sync",
			"GET /api/v1/server/mail",
			"PUT /api/v1/server/mail",
			"POST /api/v1/repair",
		},
	})
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) handleAccounts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListAccounts(w)
	case http.MethodPost:
		s.handleLoginAccount(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Service) handleListAccounts(w http.ResponseWriter) {
	userIDs := s.bridge.GetUserIDs()
	accounts := make([]accountResponse, 0, len(userIDs))

	for _, userID := range userIDs {
		userInfo, err := s.bridge.GetUserInfo(userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load user %q: %v", userID, err))
			return
		}

		accounts = append(accounts, s.accountFromUserInfo(userInfo))
	}

	writeJSON(w, http.StatusOK, map[string]any{"accounts": accounts})
}

func (s *Service) handleLoginAccount(w http.ResponseWriter, r *http.Request) {
	request := loginRequest{}
	if err := decodeJSONBody(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || request.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	userID, err := s.bridge.LoginFull(
		context.Background(),
		request.Username,
		[]byte(request.Password),
		func() (string, error) {
			if request.TOTP == "" {
				return "", fmt.Errorf("2FA code is required for this account")
			}
			return request.TOTP, nil
		},
		func() ([]byte, error) {
			if request.MailboxPassword == "" {
				return nil, fmt.Errorf("mailbox password is required for this account")
			}
			return []byte(request.MailboxPassword), nil
		},
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to login account: %v", err))
		return
	}

	userInfo, err := s.bridge.GetUserInfo(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to load logged in account: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, s.accountFromUserInfo(userInfo))
}

func (s *Service) handleAccountByID(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/accounts/")
	segments := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(segments) < 1 || segments[0] == "" {
		writeError(w, http.StatusNotFound, "account route not found")
		return
	}

	userID := segments[0]

	if len(segments) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.handleGetAccount(w, userID)
		case http.MethodDelete:
			s.handleDeleteAccount(w, userID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	if len(segments) != 2 {
		writeError(w, http.StatusNotFound, "account route not found")
		return
	}

	switch segments[1] {
	case "logout":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		s.handleLogoutAccount(w, userID)
	case "sync":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		s.handleResyncAccount(w, userID)
	default:
		writeError(w, http.StatusNotFound, "account route not found")
	}
}

func (s *Service) handleGetAccount(w http.ResponseWriter, userID string) {
	userInfo, err := s.bridge.GetUserInfo(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("user not found: %s", userID))
		return
	}

	writeJSON(w, http.StatusOK, s.accountFromUserInfo(userInfo))
}

func (s *Service) handleLogoutAccount(w http.ResponseWriter, userID string) {
	if err := s.bridge.LogoutUser(context.Background(), userID); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to logout user: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *Service) handleDeleteAccount(w http.ResponseWriter, userID string) {
	if err := s.bridge.DeleteUser(context.Background(), userID); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to remove user: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (s *Service) handleResyncAccount(w http.ResponseWriter, userID string) {
	if err := s.bridge.SendBadEventUserFeedback(context.Background(), userID, true); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to trigger sync: %v", err))
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sync requested"})
}

func (s *Service) handleMailSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.getMailSettings())

	case http.MethodPut:
		var request mailServerSettings
		if err := decodeJSONBody(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		if err := validatePort(request.IMAPPort); err != nil {
			writeError(w, http.StatusBadRequest, "invalid IMAP port")
			return
		}

		if err := validatePort(request.SMTPPort); err != nil {
			writeError(w, http.StatusBadRequest, "invalid SMTP port")
			return
		}

		ctx := context.Background()

		if s.bridge.GetIMAPSSL() != request.UseSSLForIMAP {
			if err := s.bridge.SetIMAPSSL(ctx, request.UseSSLForIMAP); err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to set IMAP SSL: %v", err))
				return
			}
		}

		if s.bridge.GetSMTPSSL() != request.UseSSLForSMTP {
			if err := s.bridge.SetSMTPSSL(ctx, request.UseSSLForSMTP); err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to set SMTP SSL: %v", err))
				return
			}
		}

		if s.bridge.GetIMAPPort() != request.IMAPPort {
			if err := s.bridge.SetIMAPPort(ctx, request.IMAPPort); err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to set IMAP port: %v", err))
				return
			}
		}

		if s.bridge.GetSMTPPort() != request.SMTPPort {
			if err := s.bridge.SetSMTPPort(ctx, request.SMTPPort); err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to set SMTP port: %v", err))
				return
			}
		}

		writeJSON(w, http.StatusOK, s.getMailSettings())

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Service) handleRepair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.bridge.Repair()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "repair requested"})
}

func (s *Service) getMailSettings() mailServerSettings {
	return mailServerSettings{
		Host:          constants.Host,
		IMAPPort:      s.bridge.GetIMAPPort(),
		SMTPPort:      s.bridge.GetSMTPPort(),
		UseSSLForIMAP: s.bridge.GetIMAPSSL(),
		UseSSLForSMTP: s.bridge.GetSMTPSSL(),
	}
}

func (s *Service) accountFromUserInfo(userInfo bridge.UserInfo) accountResponse {
	return accountResponse{
		ID:          userInfo.UserID,
		Username:    userInfo.Username,
		State:       userStateToString(userInfo.State),
		Addresses:   userInfo.Addresses,
		AddressMode: userInfo.AddressMode.String(),
		Password:    string(userInfo.BridgePass),
		UsedSpace:   userInfo.UsedSpace,
		MaxSpace:    userInfo.MaxSpace,
		Sync:        s.getSyncStatus(userInfo.UserID),
	}
}

func userStateToString(state bridge.UserState) string {
	switch state {
	case bridge.SignedOut:
		return "signed_out"
	case bridge.Locked:
		return "locked"
	case bridge.Connected:
		return "connected"
	default:
		return "unknown"
	}
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port")
	}
	return nil
}

func validateAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid web address %q: %w", address, err)
	}

	switch host {
	case "127.0.0.1", "::1", "localhost":
		return nil
	default:
		if allowNonLoopback() {
			return nil
		}

		return fmt.Errorf("web admin address must be loopback, got %q", host)
	}
}

func allowNonLoopback() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("BRIDGE_WEB_ALLOW_NON_LOOPBACK")))
	return v == "1" || v == "true" || v == "yes"
}

func decodeJSONBody(r *http.Request, out any) error {
	defer func() {
		_ = r.Body.Close()
	}()

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1024*1024))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid JSON request body: %w", err)
	}

	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request body must contain only one JSON object")
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.WithError(err).Error("Failed to write response")
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
