package social

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/grafana/grafana/pkg/models"

	"golang.org/x/oauth2"
	"io/ioutil"
	"github.com/grafana/grafana/pkg/infra/log"
)

type SocialPhabricatorOAuth struct {
	*SocialBase
	allowedDomains       []string
	allowedOrganizations []string
	apiUrl               string
	allowSignup          bool
	teamIds              []int
}

type PhabricatorUserInfoJson struct {
	Phid        string `json:"phid"`
	Name        string `json:"realName"`
	DisplayName string `json:"realName"`
	Username    string `json:"userName"`
	Email       string `json:"primaryEmail"`
}

type ResultJson struct {
	Result PhabricatorUserInfoJson `json:"result"`
}

func (s *SocialPhabricatorOAuth) Type() int {
	return int(models.GENERIC)
}

func (s *SocialPhabricatorOAuth) IsEmailAllowed(email string) bool {
	return isEmailAllowed(email, s.allowedDomains)
}

func (s *SocialPhabricatorOAuth) IsSignupAllowed() bool {
	return s.allowSignup
}

func (s *SocialPhabricatorOAuth) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	var data ResultJson

	if !s.extractToken(&data, token) {
		response, err := PhabricatorHttpGet(client, s.apiUrl, token.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("Error getting user info: %s", err)
		}

		err = json.Unmarshal(response.Body, &data)
		if err != nil {
			return nil, fmt.Errorf("Error decoding user info JSON: %s", err)
		}
	}

	id := s.extractId(&data)

	email := s.extractEmail(&data)

	login := s.extractUsername(&data, email)

	name := s.extractName(&data, login)

	userInfo := &BasicUserInfo{
		Id:    id,
		Name:  name,
		Login: login,
		Email: email,
	}

	return userInfo, nil
}

func PhabricatorHttpGet(client *http.Client, url string, token string) (response HttpGetResponse, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	q := req.URL.Query()
	q.Add("access_token", token)

	req.URL.RawQuery = q.Encode()

	rsp, err := client.Do(req)
	if err != nil {
		return
	}

	defer rsp.Body.Close()

	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return
	}

	response = HttpGetResponse{body, rsp.Header}

	if rsp.StatusCode >= 300 {
		err = fmt.Errorf(string(response.Body))
		return
	}

	log.Trace("HTTP GET %s: %s %s", url, rsp.Status, string(response.Body))

	err = nil
	return
}

func (s *SocialPhabricatorOAuth) extractToken(data *ResultJson, token *oauth2.Token) bool {

	idToken := token.Extra("id_token")
	if idToken == nil {
		s.log.Debug("No id_token found", "token", token)
		return false
	}

	jwtRegexp := regexp.MustCompile("^([-_a-zA-Z0-9]+)[.]([-_a-zA-Z0-9]+)[.]([-_a-zA-Z0-9]+)$")
	matched := jwtRegexp.FindStringSubmatch(idToken.(string))
	if matched == nil {
		s.log.Debug("id_token is not in JWT format", "id_token", idToken.(string))
		return false
	}

	payload, err := base64.RawURLEncoding.DecodeString(matched[2])
	if err != nil {
		s.log.Error("Error base64 decoding id_token", "raw_payload", matched[2], "err", err)
		return false
	}

	err = json.Unmarshal(payload, data)
	if err != nil {
		s.log.Error("Error decoding id_token JSON", "payload", string(payload), "err", err)
		return false
	}

	email := s.extractEmail(data)
	if email == "" {
		s.log.Debug("No email found in id_token", "json", string(payload), "data", data)
		return false
	}

	s.log.Debug("Received id_token", "json", string(payload), "data", data)
	return true
}

func (s *SocialPhabricatorOAuth) extractEmail(data *ResultJson) string {
	if data.Result.Email != "" {
		return data.Result.Email
	}

	return ""
}

func (s *SocialPhabricatorOAuth) extractUsername(data *ResultJson, email string) string {

	if data.Result.Username != "" {
		return data.Result.Username
	}

	return email
}

func (s *SocialPhabricatorOAuth) extractName(data *ResultJson, username string) string {

	if data.Result.Name != "" {
		return data.Result.Name
	}

	return username
}
func (s *SocialPhabricatorOAuth) extractId(data *ResultJson) string {
	if data.Result.Phid != "" {
		return data.Result.Phid
	}

	return ""
}
