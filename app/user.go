// Copyright (c) 2016 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"io"
	"strconv"
	"strings"

	l4g "github.com/alecthomas/log4go"
	"github.com/mattermost/platform/einterfaces"
	"github.com/mattermost/platform/model"
	"github.com/mattermost/platform/utils"
)

func CreateUser(user *model.User) (*model.User, *model.AppError) {

	user.Roles = model.ROLE_SYSTEM_USER.Id

	// Below is a special case where the first user in the entire
	// system is granted the system_admin role
	if result := <-Srv.Store.User().GetTotalUsersCount(); result.Err != nil {
		return nil, result.Err
	} else {
		count := result.Data.(int64)
		if count <= 0 {
			user.Roles = model.ROLE_SYSTEM_ADMIN.Id + " " + model.ROLE_SYSTEM_USER.Id
		}
	}

	user.MakeNonNil()
	user.Locale = *utils.Cfg.LocalizationSettings.DefaultClientLocale

	if err := utils.IsPasswordValid(user.Password); user.AuthService == "" && err != nil {
		return nil, err
	}

	if result := <-Srv.Store.User().Save(user); result.Err != nil {
		l4g.Error(utils.T("api.user.create_user.save.error"), result.Err)
		return nil, result.Err
	} else {
		ruser := result.Data.(*model.User)

		if user.EmailVerified {
			if cresult := <-Srv.Store.User().VerifyEmail(ruser.Id); cresult.Err != nil {
				l4g.Error(utils.T("api.user.create_user.verified.error"), cresult.Err)
			}
		}

		pref := model.Preference{UserId: ruser.Id, Category: model.PREFERENCE_CATEGORY_TUTORIAL_STEPS, Name: ruser.Id, Value: "0"}
		if presult := <-Srv.Store.Preference().Save(&model.Preferences{pref}); presult.Err != nil {
			l4g.Error(utils.T("api.user.create_user.tutorial.error"), presult.Err.Message)
		}

		ruser.Sanitize(map[string]bool{})

		// This message goes to everyone, so the teamId, channelId and userId are irrelevant
		message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_NEW_USER, "", "", "", nil)
		message.Add("user_id", ruser.Id)
		go Publish(message)

		return ruser, nil
	}
}

func CreateOAuthUser(service string, userData io.Reader, teamId string) (*model.User, *model.AppError) {
	var user *model.User
	provider := einterfaces.GetOauthProvider(service)
	if provider == nil {
		return nil, model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.not_available.app_error", map[string]interface{}{"Service": strings.Title(service)}, "")
	} else {
		user = provider.GetUserFromJson(userData)
	}

	if user == nil {
		return nil, model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.create.app_error", map[string]interface{}{"Service": service}, "")
	}

	suchan := Srv.Store.User().GetByAuth(user.AuthData, service)
	euchan := Srv.Store.User().GetByEmail(user.Email)

	found := true
	count := 0
	for found {
		if found = IsUsernameTaken(user.Username); found {
			user.Username = user.Username + strconv.Itoa(count)
			count += 1
		}
	}

	if result := <-suchan; result.Err == nil {
		return nil, model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.already_used.app_error", map[string]interface{}{"Service": service}, "email="+user.Email)
	}

	if result := <-euchan; result.Err == nil {
		authService := result.Data.(*model.User).AuthService
		if authService == "" {
			return nil, model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.already_attached.app_error",
				map[string]interface{}{"Service": service, "Auth": model.USER_AUTH_SERVICE_EMAIL}, "email="+user.Email)
		} else {
			return nil, model.NewLocAppError("CreateOAuthUser", "api.user.create_oauth_user.already_attached.app_error",
				map[string]interface{}{"Service": service, "Auth": authService}, "email="+user.Email)
		}
	}

	user.EmailVerified = true

	ruser, err := CreateUser(user)
	if err != nil {
		return nil, err
	}

	if len(teamId) > 0 {
		err = JoinUserToTeamById(teamId, user)
		if err != nil {
			return nil, err
		}

		err = AddDirectChannels(teamId, user)
		if err != nil {
			l4g.Error(err.Error())
		}
	}

	return ruser, nil
}

// Check if the username is already used by another user. Return false if the username is invalid.
func IsUsernameTaken(name string) bool {

	if !model.IsValidUsername(name) {
		return false
	}

	if result := <-Srv.Store.User().GetByUsername(name); result.Err != nil {
		return false
	} else {
		return true
	}

	return false
}
