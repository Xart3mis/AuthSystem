package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/Xart3mis/AuthSystem/controllers"
	"github.com/Xart3mis/AuthSystem/database"
	"github.com/Xart3mis/AuthSystem/initializers"
	"github.com/Xart3mis/AuthSystem/utils"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

func init() {}

func main() {
	e := echo.New()

	currentDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalln(err)
	}

	_, err = initializers.LoadConfig(currentDir)
	if err != nil {
		e.Logger.Fatal(err)
	}

	err = database.ConnectDB(database.ConfigDB{
		Host:     initializers.AppConfig.DBHost,
		Port:     initializers.AppConfig.DBPort,
		Username: initializers.AppConfig.DBUserName,
		Password: initializers.AppConfig.DBUserPassword,
		DB:       initializers.AppConfig.DBName,
	})
	if err != nil {
		e.Logger.Fatal(err)
	}

	err = initializers.ConnectRedis(&initializers.AppConfig)
	if err != nil {
		e.Logger.Fatal(err)
	}

	e.Use(middleware.Recover())
	e.Use(middleware.Logger())

	jwtConfig := echojwt.WithConfig(echojwt.Config{
		TokenLookup: "header:Authorization:Bearer ,cookie:access_token",
		ParseTokenFunc: func(c echo.Context, token string) (interface{}, error) {
			details, err := utils.ValidateToken(token, initializers.AppConfig.AccessTokenPublicKey)
			if err != nil {
				return c.JSON(http.StatusForbidden, echo.Map{"message": err.Error()}), err
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			_, err = initializers.RedisClient.Get(ctx, details.TokenUuid).Result()
			if err == redis.Nil {
				return c.JSON(http.StatusForbidden, echo.Map{"message": "Token is invalid or session has expired"}), err
			}

			q := database.GetQuery()
			user, err := q.User.WithContext(ctx).Where(q.User.Username.Eq(details.Username)).First()
			if err != nil {
				if err == gorm.ErrRecordNotFound {
					return c.JSON(http.StatusForbidden, echo.Map{"message": "the user belonging to this token no logger exists"}), err
				} else {
					return c.JSON(http.StatusBadGateway, echo.Map{"message": err.Error()}), err
				}
			}

			return user, nil
		},
	})

	api := e.Group("/api")

	g := api.Group("/auth")
	g.POST("/register", controllers.RegisterController)
	g.POST("/login", controllers.LoginController)
	g.GET("/refresh", controllers.RefreshController)

	api.GET("/users/me", controllers.UserController, jwtConfig)

	e.File("/", filepath.Join(currentDir, "html/home.html"))
	e.File("/login", filepath.Join(currentDir, "html/login.html"))
	e.File("/register", filepath.Join(currentDir, "html/register.html"))

	go func() {
		if err := e.Start(fmt.Sprintf(":%s", initializers.AppConfig.ServerPort)); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}
