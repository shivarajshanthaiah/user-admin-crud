package models

import (
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// User credentials
type Credentials struct {
	gorm.Model
	Username string `gorm:"unique"`
	Email    string `gorm:"unique"`
	Password string `gorm:"unique"`
}

// claims encoding into JWT
type Claims struct {
	Id        uint   `json:"id"`
	UserEmail string `json:"useremail"`
	jwt.RegisteredClaims
}
