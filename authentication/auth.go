package authentication

import (
	"log"
	"net/http"
	"os"
	"user_admin_crud/configuration"
	"user_admin_crud/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// user authentication
func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("jwtToken")
		if err != nil || token == "" {
			c.Redirect(http.StatusSeeOther, "/au/login")
			c.Abort()
			return
		}

		// Parse and validate JWT token.
		useremail, err := ParseToken(token)
		if err != nil || useremail == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		}

		// Retrieve user information from the database using email
		user, err := GetUserByUserEmail(useremail)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		}

		// Set user email and information in Gin context
		c.Set("email", useremail)
		c.Set("user", user)

		// Continue processing the middleware chain
		c.Next()
	}
}

// admin authentication
func AdminAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenCookie, err := c.Cookie("Admin")
		if err != nil || tokenCookie == "" {
			c.Redirect(http.StatusSeeOther, "/admin-login")
			return
		}

		// Parse and validate admin JWT token
		useremail, err := ParseToken(tokenCookie)
		if err != nil || useremail == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		}

		// Load environment variables
		err = godotenv.Load(".env")
		if err != nil {
			log.Fatal("Error loading .env file")
		}

		if useremail != os.Getenv("Admin_Email") {
			c.Redirect(http.StatusSeeOther, "/admin-login")
			return
		}

		c.Next()
	}
}

//retrieves user information from the database
func GetUserByUserEmail(email string) (*models.Credentials, error) {
	var user models.Credentials
	if err := configuration.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// Set cache-control headers to prevent caching
func ClearCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		c.Next()
	}
}
