// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.
// Code generated by gorm.io/gen. DO NOT EDIT.

package model

const TableNameUser = "Users"

// User mapped from table <Users>
type User struct {
	Username string `gorm:"column:Username;primaryKey" json:"Username"`
	Password string `gorm:"column:Password;not null" json:"Password"`
}

// TableName User's table name
func (*User) TableName() string {
	return TableNameUser
}
