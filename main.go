package main

import (
	"user_admin_crud/configuration"
	"user_admin_crud/routes"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	configuration.ConfigDB()

	store := cookie.NewStore([]byte("1011"))
	r.Use(sessions.Sessions("login-session", store))

	routes.RoutesConfig(r,configuration.DB)
	r.Run("localhost:7000")

}