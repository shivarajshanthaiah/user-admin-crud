package routes

import (
	"user_admin_crud/authentication"
	"user_admin_crud/configuration"
	"user_admin_crud/handlers"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Route configuration using gin Engine and Gorm database instance
func RoutesConfig(r *gin.Engine, db *gorm.DB) {
	authMiddleware := authentication.Authenticate()
	r.Static("/static", "./static")
	r.LoadHTMLGlob("templates/*.html")
	r.Use(authentication.ClearCache())

	// Group for authentication-related routes
	authGroup := r.Group("/au")
	authGroup.Use(configuration.DatabaseMiddleware(db))
	{
		authGroup.GET("/login", handlers.LoginPage)
		authGroup.GET("/signup", handlers.SignupPage)
		authGroup.POST("/login", handlers.LoginAuthentication)
		authGroup.POST("/signup", handlers.SignupForm)
	}

	// Group for protected routes
	protectedGroup := r.Group("/pr")
	protectedGroup.Use(authMiddleware)
	protectedGroup.Use(configuration.DatabaseMiddleware(db))
	{
		protectedGroup.GET("/home", handlers.HomePage)
		protectedGroup.GET("/logout", handlers.Logout)
	}

	// Group for admin-related routes
	adminGroup := r.Group("/su")
	adminGroup.Use(authentication.AdminAuthentication())
	r.GET("/admin-login", handlers.AdminLoginPage)
	r.POST("/admin-login", handlers.AdminAuthentication)
	{
		adminGroup.GET("/admin-panel", handlers.AdminPanel)
		adminGroup.GET("adminlogout", handlers.AdminLogout)
		adminGroup.POST("/adduser", handlers.AddNewUser)
		adminGroup.GET("/search", handlers.SearchUser)
		adminGroup.POST("/edituser/:id", handlers.EditUser)
		adminGroup.GET("/deleteuser/:id", handlers.DeleteUser)
	}
}
