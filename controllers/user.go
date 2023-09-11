package controllers

import (
	"fmt"
	"net/http"

	"github.com/Xart3mis/AuthSystem/database/dao/model"
	"github.com/labstack/echo/v4"
)

func UserController(c echo.Context) error {
	user, ok := c.Get("user").(*model.User)
	if !ok {
		return c.JSON(http.StatusUnprocessableEntity, echo.Map{"message": "failed to cast user"})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": fmt.Sprintf("Welcome %s!", user.Username),
	})
}
