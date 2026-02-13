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

package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/proton-bridge/v3/internal/bridge"
	"github.com/ProtonMail/proton-bridge/v3/internal/events"
	"github.com/ProtonMail/proton-bridge/v3/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServiceValidation(t *testing.T) {
	bridge := newFakeBridge()
	eventCh := make(chan events.Event)
	quitCh := make(chan struct{})

	_, err := newService(bridge, eventCh, quitCh, Config{
		Address:   "127.0.0.1:8081",
		AdminPass: "pass",
	})
	require.ErrorContains(t, err, "missing web admin user")

	_, err = newService(bridge, eventCh, quitCh, Config{
		Address:   "127.0.0.1:8081",
		AdminUser: "root",
	})
	require.ErrorContains(t, err, "missing web admin password")

	_, err = newService(bridge, eventCh, quitCh, Config{
		Address:   "0.0.0.0:8081",
		AdminUser: "root",
		AdminPass: "pass",
	})
	require.ErrorContains(t, err, "must be loopback")

	t.Setenv("BRIDGE_WEB_ALLOW_NON_LOOPBACK", "true")
	_, err = newService(bridge, eventCh, quitCh, Config{
		Address:   "0.0.0.0:8081",
		AdminUser: "root",
		AdminPass: "pass",
	})
	require.NoError(t, err)
}

func TestAccountsAuthAndList(t *testing.T) {
	t.Parallel()

	bridge := newFakeBridge()
	bridge.users["u1"] = sampleUserInfo("u1", "user@example.com")
	bridge.userIDs = []string{"u1"}

	service := mustNewTestService(t, bridge)

	unauthorized := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
	unauthorizedResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(unauthorizedResp, unauthorized)
	assert.Equal(t, http.StatusUnauthorized, unauthorizedResp.Code)

	wrongAuth := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
	wrongAuth.SetBasicAuth("bad", "creds")
	wrongAuthResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(wrongAuthResp, wrongAuth)
	assert.Equal(t, http.StatusUnauthorized, wrongAuthResp.Code)

	authorized := authedRequest(http.MethodGet, "/api/v1/accounts", "")
	authorizedResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(authorizedResp, authorized)
	require.Equal(t, http.StatusOK, authorizedResp.Code)

	var payload struct {
		Accounts []accountResponse `json:"accounts"`
	}
	require.NoError(t, json.Unmarshal(authorizedResp.Body.Bytes(), &payload))
	require.Len(t, payload.Accounts, 1)
	assert.Equal(t, "user@example.com", payload.Accounts[0].Username)
	assert.Equal(t, "unknown", payload.Accounts[0].Sync.State)
}

func TestAccountLogin(t *testing.T) {
	t.Parallel()

	bridge := newFakeBridge()
	bridge.users["u1"] = sampleUserInfo("u1", "login@example.com")
	bridge.userIDs = []string{"u1"}
	bridge.loginResultUserID = "u1"

	service := mustNewTestService(t, bridge)

	loginResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(loginResp, authedRequest(http.MethodPost, "/api/v1/accounts", `{"username":"login@example.com","password":"secret"}`))
	require.Equal(t, http.StatusCreated, loginResp.Code)

	var payload accountResponse
	require.NoError(t, json.Unmarshal(loginResp.Body.Bytes(), &payload))
	assert.Equal(t, "u1", payload.ID)
	assert.Equal(t, "login@example.com", payload.Username)

	bridge.requireTOTP = true
	missingTOTPResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(missingTOTPResp, authedRequest(http.MethodPost, "/api/v1/accounts", `{"username":"login@example.com","password":"secret"}`))
	require.Equal(t, http.StatusBadRequest, missingTOTPResp.Code)
	assert.Contains(t, missingTOTPResp.Body.String(), "2FA code is required")

	withTOTPResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(withTOTPResp, authedRequest(http.MethodPost, "/api/v1/accounts", `{"username":"login@example.com","password":"secret","totp":"123456"}`))
	require.Equal(t, http.StatusCreated, withTOTPResp.Code)

	bridge.requireTOTP = false
	bridge.requireMailboxPassword = true
	missingMailboxResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(missingMailboxResp, authedRequest(http.MethodPost, "/api/v1/accounts", `{"username":"login@example.com","password":"secret"}`))
	require.Equal(t, http.StatusBadRequest, missingMailboxResp.Code)
	assert.Contains(t, missingMailboxResp.Body.String(), "mailbox password is required")
}

func TestAccountLoginPayloadValidation(t *testing.T) {
	t.Parallel()

	bridge := newFakeBridge()
	service := mustNewTestService(t, bridge)

	unknownFieldResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(unknownFieldResp, authedRequest(http.MethodPost, "/api/v1/accounts", `{"username":"user@example.com","password":"secret","extra":"x"}`))
	require.Equal(t, http.StatusBadRequest, unknownFieldResp.Code)
	assert.Contains(t, unknownFieldResp.Body.String(), "invalid JSON request body")

	multiObjectResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(multiObjectResp, authedRequest(http.MethodPost, "/api/v1/accounts", `{"username":"user@example.com","password":"secret"}{"other":"object"}`))
	require.Equal(t, http.StatusBadRequest, multiObjectResp.Code)
	assert.Contains(t, multiObjectResp.Body.String(), "only one JSON object")
}

func TestAccountOperations(t *testing.T) {
	t.Parallel()

	bridge := newFakeBridge()
	bridge.users["u1"] = sampleUserInfo("u1", "ops@example.com")
	bridge.userIDs = []string{"u1"}

	service := mustNewTestService(t, bridge)

	getResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(getResp, authedRequest(http.MethodGet, "/api/v1/accounts/u1", ""))
	require.Equal(t, http.StatusOK, getResp.Code)

	logoutResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(logoutResp, authedRequest(http.MethodPost, "/api/v1/accounts/u1/logout", ""))
	require.Equal(t, http.StatusOK, logoutResp.Code)
	assert.Equal(t, []string{"u1"}, bridge.logoutCalls)

	syncResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(syncResp, authedRequest(http.MethodPost, "/api/v1/accounts/u1/sync", ""))
	require.Equal(t, http.StatusAccepted, syncResp.Code)
	assert.Equal(t, []string{"u1"}, bridge.syncCalls)

	deleteResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(deleteResp, authedRequest(http.MethodDelete, "/api/v1/accounts/u1", ""))
	require.Equal(t, http.StatusOK, deleteResp.Code)
	assert.Equal(t, []string{"u1"}, bridge.deleteCalls)

	notFoundResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(notFoundResp, authedRequest(http.MethodGet, "/api/v1/accounts/nope", ""))
	require.Equal(t, http.StatusNotFound, notFoundResp.Code)
}

func TestMailServerSettings(t *testing.T) {
	t.Parallel()

	bridge := newFakeBridge()
	bridge.imapPort = 1143
	bridge.smtpPort = 1025
	bridge.imapSSL = true
	bridge.smtpSSL = false

	service := mustNewTestService(t, bridge)

	getResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(getResp, authedRequest(http.MethodGet, "/api/v1/server/mail", ""))
	require.Equal(t, http.StatusOK, getResp.Code)
	assert.Contains(t, getResp.Body.String(), `"imapPort":1143`)

	invalidResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(invalidResp, authedRequest(http.MethodPut, "/api/v1/server/mail", `{"imapPort":0,"smtpPort":1025,"useSSLForImap":true,"useSSLForSmtp":false}`))
	require.Equal(t, http.StatusBadRequest, invalidResp.Code)

	updateResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(updateResp, authedRequest(http.MethodPut, "/api/v1/server/mail", `{"imapPort":2143,"smtpPort":2025,"useSSLForImap":false,"useSSLForSmtp":true}`))
	require.Equal(t, http.StatusOK, updateResp.Code)
	assert.Equal(t, 2143, bridge.imapPort)
	assert.Equal(t, 2025, bridge.smtpPort)
	assert.False(t, bridge.imapSSL)
	assert.True(t, bridge.smtpSSL)
}

func TestRepairAndMethodGuards(t *testing.T) {
	t.Parallel()

	bridge := newFakeBridge()
	service := mustNewTestService(t, bridge)

	okResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(okResp, authedRequest(http.MethodPost, "/api/v1/repair", ""))
	require.Equal(t, http.StatusAccepted, okResp.Code)
	assert.Equal(t, 1, bridge.repairCalls)

	methodResp := httptest.NewRecorder()
	service.server.Handler.ServeHTTP(methodResp, authedRequest(http.MethodGet, "/api/v1/repair", ""))
	require.Equal(t, http.StatusMethodNotAllowed, methodResp.Code)
}

func TestSyncStatusEvents(t *testing.T) {
	t.Parallel()

	bridge := newFakeBridge()
	eventCh := make(chan events.Event, 3)
	service, err := newService(bridge, eventCh, make(chan struct{}), testConfig())
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		service.watchEvents()
		close(done)
	}()

	eventCh <- events.SyncStarted{UserID: "u1"}
	eventCh <- events.SyncProgress{UserID: "u1", Progress: 0.5, Elapsed: 2 * time.Second, Remaining: 3 * time.Second}
	eventCh <- events.SyncFailed{UserID: "u1", Error: errors.New("sync failed")}
	close(eventCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchEvents did not finish")
	}

	status := service.getSyncStatus("u1")
	assert.Equal(t, "failed", status.State)
	assert.Equal(t, "sync failed", status.Error)
}

func mustNewTestService(t *testing.T, bridge *fakeBridge) *Service {
	t.Helper()
	service, err := newService(bridge, make(chan events.Event), make(chan struct{}), testConfig())
	require.NoError(t, err)
	return service
}

func testConfig() Config {
	return Config{
		Address:   "127.0.0.1:8081",
		AdminUser: "root",
		AdminPass: "pass",
	}
}

func authedRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.SetBasicAuth("root", "pass")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func sampleUserInfo(userID, username string) bridge.UserInfo {
	return bridge.UserInfo{
		UserID:      userID,
		Username:    username,
		State:       bridge.Connected,
		Addresses:   []string{username},
		AddressMode: vault.CombinedMode,
		BridgePass:  []byte("bridge-pass"),
		UsedSpace:   100,
		MaxSpace:    1000,
	}
}

type fakeBridge struct {
	lock sync.Mutex

	userIDs []string
	users   map[string]bridge.UserInfo

	loginResultUserID      string
	loginErr               error
	requireTOTP            bool
	requireMailboxPassword bool

	logoutCalls []string
	deleteCalls []string
	syncCalls   []string
	repairCalls int

	imapPort int
	smtpPort int
	imapSSL  bool
	smtpSSL  bool
}

func newFakeBridge() *fakeBridge {
	return &fakeBridge{
		userIDs:  make([]string, 0),
		users:    make(map[string]bridge.UserInfo),
		imapPort: 1143,
		smtpPort: 1025,
	}
}

func (f *fakeBridge) GetUserIDs() []string {
	f.lock.Lock()
	defer f.lock.Unlock()
	ids := make([]string, len(f.userIDs))
	copy(ids, f.userIDs)
	return ids
}

func (f *fakeBridge) GetUserInfo(userID string) (bridge.UserInfo, error) {
	f.lock.Lock()
	defer f.lock.Unlock()
	user, ok := f.users[userID]
	if !ok {
		return bridge.UserInfo{}, errors.New("no such user")
	}
	return user, nil
}

func (f *fakeBridge) LoginFull(
	_ context.Context,
	_ string,
	_ []byte,
	getTOTP func() (string, error),
	getKeyPass func() ([]byte, error),
) (string, error) {
	f.lock.Lock()
	requireTOTP := f.requireTOTP
	requireMailbox := f.requireMailboxPassword
	loginErr := f.loginErr
	userID := f.loginResultUserID
	f.lock.Unlock()

	if requireTOTP {
		if _, err := getTOTP(); err != nil {
			return "", err
		}
	}

	if requireMailbox {
		if _, err := getKeyPass(); err != nil {
			return "", err
		}
	}

	if loginErr != nil {
		return "", loginErr
	}

	return userID, nil
}

func (f *fakeBridge) LogoutUser(_ context.Context, userID string) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	if _, ok := f.users[userID]; !ok {
		return errors.New("no such user")
	}
	f.logoutCalls = append(f.logoutCalls, userID)
	return nil
}

func (f *fakeBridge) DeleteUser(_ context.Context, userID string) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	if _, ok := f.users[userID]; !ok {
		return errors.New("no such user")
	}
	f.deleteCalls = append(f.deleteCalls, userID)
	return nil
}

func (f *fakeBridge) SendBadEventUserFeedback(_ context.Context, userID string, doResync bool) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	if !doResync {
		return errors.New("resync disabled")
	}
	if _, ok := f.users[userID]; !ok {
		return errors.New("no such user")
	}
	f.syncCalls = append(f.syncCalls, userID)
	return nil
}

func (f *fakeBridge) GetIMAPPort() int {
	f.lock.Lock()
	defer f.lock.Unlock()
	return f.imapPort
}

func (f *fakeBridge) SetIMAPPort(_ context.Context, newPort int) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.imapPort = newPort
	return nil
}

func (f *fakeBridge) GetIMAPSSL() bool {
	f.lock.Lock()
	defer f.lock.Unlock()
	return f.imapSSL
}

func (f *fakeBridge) SetIMAPSSL(_ context.Context, newSSL bool) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.imapSSL = newSSL
	return nil
}

func (f *fakeBridge) GetSMTPPort() int {
	f.lock.Lock()
	defer f.lock.Unlock()
	return f.smtpPort
}

func (f *fakeBridge) SetSMTPPort(_ context.Context, newPort int) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.smtpPort = newPort
	return nil
}

func (f *fakeBridge) GetSMTPSSL() bool {
	f.lock.Lock()
	defer f.lock.Unlock()
	return f.smtpSSL
}

func (f *fakeBridge) SetSMTPSSL(_ context.Context, newSSL bool) error {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.smtpSSL = newSSL
	return nil
}

func (f *fakeBridge) Repair() {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.repairCalls++
}
