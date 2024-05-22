package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AccessToken represents the BTP access token.
type AccessToken struct {
	Value     string
	ExpiresAt time.Time
}

// AccessTokenManager manages the BTP access tokens and their caching.
type AccessTokenManager struct {
	mutex      sync.Mutex
	tokenCache map[string]*AccessToken
}

// AccessTokenResponse represents the structure of the token response JSON.
type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Jti         string `json:"jti"`
}

// NewAccessTokenManager creates a new AccessTokenManager instance.
func NewAccessTokenManager() *AccessTokenManager {
	return &AccessTokenManager{
		tokenCache: make(map[string]*AccessToken),
	}
}

// GetAccessToken retrieves the BTP token. If a valid token is available in the cache, it returns it.
// Otherwise, it generates a new accessToken using the client ID and secret.
func (tm *AccessTokenManager) GetAccessToken(clientID, clientSecret, uaaUrl string) (string, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Check if a valid token exists in the cache
	if token, ok := tm.tokenCache[clientID]; ok && time.Now().Before(token.ExpiresAt) {
		return token.Value, nil
	}

	// Generate a new accessToken
	newToken, err := generateAccessToken(clientID, clientSecret, uaaUrl)
	if err != nil {
		return "", err
	}
	tm.tokenCache[clientID] = newToken

	return newToken.Value, nil
}

func generateAccessToken(clientID, clientSecret, uaaUrl string) (*AccessToken, error) {
	url := uaaUrl + "/oauth/token?grant_type=client_credentials"
	payload := ""

	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	encodedCredential := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret)))
	authHeader := fmt.Sprintf("Basic %s", encodedCredential)
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp AccessTokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return nil, err
	}

	accessToken := &AccessToken{
		Value:     tokenResp.AccessToken,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	return accessToken, nil
}
