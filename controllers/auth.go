package controllers

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Xart3mis/AuthSystem/database"
	"github.com/Xart3mis/AuthSystem/database/dao/model"
	"github.com/Xart3mis/AuthSystem/initializers"
	"github.com/Xart3mis/AuthSystem/utils"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func RegisterController(c echo.Context) error {
	type RegisterBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	body := new(RegisterBody)

	if err := c.Bind(body); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": err.Error(),
		})
	}

	ctx, Cancel := context.WithCancel(context.Background())
	defer Cancel()

	q := database.GetQuery()
	if _, err := q.User.WithContext(ctx).Where(q.User.Username.Eq(body.Username)).First(); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusInternalServerError, echo.Map{
				"message": err.Error(),
			})
		}
	} else {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "Account already exists",
		})
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": err.Error(),
		})
	}

	encodedHash := base64.StdEncoding.EncodeToString(hash)

	err = q.User.WithContext(ctx).Create(&model.User{
		Username: body.Username,
		Password: encodedHash,
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "success",
	})
}

func LoginController(c echo.Context) error {
	type LoginBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	body := new(LoginBody)
	err := c.Bind(body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": err.Error(),
		})
	}

	q := database.GetQuery()

	ctx, Cancel := context.WithCancel(context.Background())
	defer Cancel()

	user, err := q.User.WithContext(ctx).Where(q.User.Username.Eq(body.Username)).First()
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusBadRequest, echo.Map{
				"message": "Account does not exist",
			})
		}

		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": err.Error(),
		})
	}

	hash, err := base64.StdEncoding.DecodeString(user.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": err.Error(),
		})
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(body.Password)); errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "Incorrect username or password",
		})
	}

	accessTokenDetails, err := utils.CreateToken(user.Username, initializers.AppConfig.AccessTokenExpiresIn, initializers.AppConfig.AccessTokenPrivateKey)
	if err != nil {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{"message": err.Error()})
	}

	refreshTokenDetails, err := utils.CreateToken(user.Username, initializers.AppConfig.RefreshTokenExpiresIn, initializers.AppConfig.RefreshTokenPrivateKey)
	if err != nil {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{"message": err.Error()})
	}

	now := time.Now()

	errAccess := initializers.RedisClient.Set(ctx, accessTokenDetails.TokenUuid, user.Username, time.Unix(*accessTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{"message": errAccess.Error()})
	}

	errRefresh := initializers.RedisClient.Set(ctx, refreshTokenDetails.TokenUuid, user.Username, time.Unix(*refreshTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{"message": errRefresh.Error()})
	}

	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    *accessTokenDetails.Token,
		Path:     "/",
		MaxAge:   initializers.AppConfig.AccessTokenMaxAge * 60,
		Secure:   false,
		HttpOnly: true,
		Domain:   strings.Split(c.Request().URL.Host, ":")[0],
	})

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    *refreshTokenDetails.Token,
		Path:     "/",
		MaxAge:   initializers.AppConfig.RefreshTokenMaxAge * 60,
		Secure:   false,
		HttpOnly: true,
		Domain:   strings.Split(c.Request().URL.Host, ":")[0],
	})

	return c.JSON(http.StatusOK, echo.Map{"message": "success", "access_token": accessTokenDetails.Token})
}

func RefreshController(c echo.Context) error {
	message := "could not refresh access token"

	refresh_token, err := c.Cookie("refresh_token")
	if err != nil {
		return c.JSON(http.StatusForbidden, echo.Map{"message": message})
	}

	ctx, Cancel := context.WithCancel(context.Background())
	defer Cancel()

	tokenClaims, err := utils.ValidateToken(refresh_token.Value, initializers.AppConfig.RefreshTokenPublicKey)
	if err != nil {
		return c.JSON(http.StatusForbidden, echo.Map{"message": err.Error()})
	}

	userid, err := initializers.RedisClient.Get(ctx, tokenClaims.TokenUuid).Result()
	if err == redis.Nil {
		return c.JSON(http.StatusForbidden, echo.Map{"message": message})
	}

	q := database.GetQuery()
	user, err := q.User.WithContext(ctx).Where(q.User.Username.Eq(userid)).First()
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.JSON(http.StatusForbidden, echo.Map{"message": "the user belonging to this token no logger exists"})
		} else {
			return c.JSON(http.StatusBadGateway, echo.Map{"message": err.Error()})
		}
	}

	accessTokenDetails, err := utils.CreateToken(user.Username, initializers.AppConfig.AccessTokenExpiresIn, initializers.AppConfig.AccessTokenPrivateKey)
	if err != nil {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{"message": err.Error()})
	}

	refreshTokenDetails, err := utils.CreateToken(user.Username, initializers.AppConfig.RefreshTokenExpiresIn, initializers.AppConfig.RefreshTokenPrivateKey)
	if err != nil {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{"message": err.Error()})
	}

	now := time.Now()

	errAccess := initializers.RedisClient.Set(ctx, accessTokenDetails.TokenUuid, user.Username, time.Unix(*accessTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{"message": errAccess.Error()})
	}

	errRefresh := initializers.RedisClient.Set(ctx, refreshTokenDetails.TokenUuid, user.Username, time.Unix(*refreshTokenDetails.ExpiresIn, 0).Sub(now)).Err()
	if errAccess != nil {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{"message": errRefresh.Error()})
	}

	c.SetCookie(&http.Cookie{
		Name:     "access_token",
		Value:    *accessTokenDetails.Token,
		Path:     "/",
		MaxAge:   initializers.AppConfig.AccessTokenMaxAge * 60,
		Secure:   false,
		HttpOnly: true,
		Domain:   strings.Split(c.Request().URL.Host, ":")[0],
	})

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    *refreshTokenDetails.Token,
		Path:     "/",
		MaxAge:   initializers.AppConfig.RefreshTokenMaxAge * 60,
		Secure:   false,
		HttpOnly: true,
		Domain:   strings.Split(c.Request().URL.Host, ":")[0],
	})

	return c.JSON(http.StatusOK, echo.Map{
		"access_token":  accessTokenDetails.Token,
		"refresh_token": refreshTokenDetails.Token,
		"message":       "success",
	})
}
