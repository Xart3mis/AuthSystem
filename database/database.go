package database

import (
	"fmt"

	"github.com/Xart3mis/AuthSystem/database/dao/query"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB

type ConfigDB struct {
	Username, Password, Host, Port, DB string
}

func ConnectDB(config ConfigDB) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True", config.Username, config.Password, config.Host, config.Port, config.DB)
  fmt.Println(dsn)
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	return nil
}

func GetQuery() *query.Query {
	return query.Use(db)
}
