package authentication

import (
	"time"
	"user_admin_crud/models"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("secret_key")

// GenerateToken
func GenerateToken(useremail string, userId uint) (string, error) {
	claims := &models.Claims{
		Id:        userId,
		UserEmail: useremail,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create a new JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key and return the signed token string
	return token.SignedString(jwtKey)
}

//parsing the provided JWT token string and returning
func ParseToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*models.Claims); ok && token.Valid {
		return claims.UserEmail, nil
	}

	return "", err
}
