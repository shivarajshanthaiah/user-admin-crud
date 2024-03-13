package handlers

import (
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"user_admin_crud/authentication"
	"user_admin_crud/configuration"
	"user_admin_crud/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// GET request to render the login page
func LoginPage(c *gin.Context) {
	tokenCookie, err := c.Cookie("jwtToken")
	if err == nil && tokenCookie != "" {
		c.Redirect(http.StatusSeeOther, "/pr/home")
		return
	}
	c.HTML(http.StatusOK, "login.html", nil)
}

// GET request to render the signup page
func SignupPage(c *gin.Context) {
	tokenCookie, err := c.Cookie("jwtToken")
	if err == nil && tokenCookie != "" {
		c.Redirect(http.StatusSeeOther, "/pr/home")
		return
	}
	c.HTML(http.StatusOK, "signup.html", nil)
}

// POST request to authenticate user login
func LoginAuthentication(c *gin.Context) {
	// Retrieve user credentials
	var temp struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	temp.Email = c.PostForm("email")
	temp.Password = c.PostForm("password")

	//Retrieve user from the db
	user, err := authentication.GetUserByUserEmail(temp.Email)
	if err != nil {
		c.HTML(http.StatusNotFound, "login.html", gin.H{"error": "User not found"})
		return
	}

	// comparing password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(temp.Password)); err == nil {
		token, err := authentication.GenerateToken(user.Email, user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		// Setting JWT token cookie and redirecting to home page
		setTokenCookie(c, token)
		c.Redirect(http.StatusSeeOther, "/pr/home")
	} else {
		// Invalid credentials, clear JWT token cookie and render login page with error
		clearCookie(c)
		c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "Invalid credentials"})
	}
}

// Function to set JWT token cookie
func setTokenCookie(c *gin.Context, token string) {
	cookie := http.Cookie{
		Name:     "jwtToken", // Cookie name
		Value:    token,      // JWT token value
		Path:     "/",        // Cookie path (root)
		HttpOnly: true,       // The cookie is accessible only through HTTP
		Secure:   false,      // Set to true in production for HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   36000, //seconds
	}
	http.SetCookie(c.Writer, &cookie)
}

// Function to clear JWT token cookie
func clearCookie(c *gin.Context) {
	cookie := http.Cookie{
		Name:     "jwtToken", // Cookie name
		Value:    "",         // Empty value to clear the cookie
		Path:     "/",        // Cookie path (root)
		HttpOnly: true,       // The cookie is accessible only through HTTP
		MaxAge:   -1,         // Expiry time in the past to delete the cookie
	}
	http.SetCookie(c.Writer, &cookie)
}

	// 	// Setting JWT token cookie and redirecting to home page
	// 	cookie := http.Cookie{
	// 		Name:     "jwtToken", // Cookie name
	// 		Value:    token,      // JWT token value
	// 		Path:     "/",        // Cookie path (root)
	// 		HttpOnly: true,       // The cookie is accessible only through HTTP
	// 		Secure:   false,      // Set to true in production for HTTPS
	// 		SameSite: http.SameSiteStrictMode,
	// 		MaxAge:   36000, //seconds
	// 	}
	// 	http.SetCookie(c.Writer, &cookie)

	// 	c.Redirect(http.StatusSeeOther, "/pr/home")
	// } else {
	// 	c.HTML(http.StatusBadRequest, "login.html", gin.H{
	// 		"error": "Invalid credentials",
	// 	})
	// }


// POST requests to process user signup
func SignupForm(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	var user models.Credentials

	user.Username = strings.TrimSpace(c.PostForm("name"))
	user.Email = strings.TrimSpace(c.PostForm("email"))
	password := c.PostForm("password")
	c_password := c.PostForm("c_password")

	// Form validation for username
	usernameRegex := regexp.MustCompile(`^[a-zA-Z]+$`)
	if !usernameRegex.MatchString(user.Username) {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "Username should only contain letters"})
		return
	}
	if len(user.Username) < 4 || len(user.Username) > 20 {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "Username must be between 4 and 20 characters"})
		return
	}

	// Form validation for email
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(user.Email) {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "Invalid email address"})
		return
	}

	if user.Username == "" || user.Email == "" || password == "" {
		c.HTML(http.StatusConflict, "signup.html", gin.H{"error": "Please fill all the details"})
		return
	}

	// for existing user
	var existingUser models.Credentials
	if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		c.HTML(http.StatusConflict, "signup.html", gin.H{"error": "Email already in use"})
		return
	} else if err != gorm.ErrRecordNotFound {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if password != c_password {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "password mismatch"})
		return
	}
	//hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	db.Create(&user)

	// continue to login
	c.HTML(http.StatusOK, "login.html", gin.H{
		"message": "Signup success, Login to continue",
	})
}

// Home page
func HomePage(c *gin.Context) {
	tokenCookie, err := c.Cookie("jwtToken")
	if err != nil || tokenCookie == "" {
		c.Redirect(http.StatusSeeOther, "/au/login")
		return
	}

	data, exists := c.Get("email")
	if !exists {
		// Handle the case where the email data doesn't exist in the context
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"message": "Email data not found in context",
		})
		return
	}

	user, ok := data.(string)
	if !ok {
		// Handle the case where the email data is not a string
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"message": "Invalid email data type in context",
		})
		return
	}

	c.HTML(http.StatusOK, "home.html", gin.H{
		"email": user,
	})
}

func Logout(c *gin.Context) {
	// clear the token
	c.SetCookie("jwtToken", "", -1, "/", "", false, true)
	//redirect to login page
	c.Redirect(http.StatusSeeOther, "/au/login")
}

// Admin Panel
func AdminLoginPage(c *gin.Context) {
	tokenCookie, err := c.Cookie("Admin")
	if err == nil && tokenCookie != "" {
		c.Redirect(http.StatusSeeOther, "/su/admin-panel")
		return
	}
	c.HTML(http.StatusOK, "admin-login.html", nil)
}

// POST request to authenticate admin login
func AdminAuthentication(c *gin.Context) {
	username := c.PostForm("admin")
	password := c.PostForm("password")

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	if username != os.Getenv("Admin_Email") || password != os.Getenv("Admin_Password") {
		c.HTML(http.StatusUnauthorized, "admin-login.html", gin.H{"error": "Invalid credentials"})

	}

	// Generate JWT token
	token, err := authentication.GenerateToken(username, 1)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Set JWT token as Admin cookie
	cookie := http.Cookie{
		Name:     "Admin", // Cookie name
		Value:    token,   // JWT token value
		Path:     "/",     // Cookie path (root)
		HttpOnly: true,    // The cookie is accessible only through HTTP
		Secure:   false,   // Set to true in production for HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   36000, //seconds
	}
	http.SetCookie(c.Writer, &cookie)

	c.Redirect(http.StatusSeeOther, "/su/admin-panel")
}

func AdminPanel(c *gin.Context) {

	// Retrieve success and error messages from query parameters
	successMessage := c.Query("success")
	errorMessage := c.Query("error")

	//// Retrieve list of users from the db
	var temp_user []models.Credentials
	result := configuration.DB.Find(&temp_user)

	if result.Error != nil {
		c.Redirect(http.StatusSeeOther, "/admin-login")
		return
	}

	// Render the admin panel
	c.HTML(http.StatusOK, "adminpanel.html", gin.H{
		"temp_user": temp_user,
		"success":   successMessage,
		"error":     errorMessage,
	})

}

// AdminLogout clears the Admin cookie
func AdminLogout(c *gin.Context) {
	c.SetCookie("Admin", "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin-login")
}

// POST request to add a new user to the db
func AddNewUser(c *gin.Context) {
	var user models.Credentials

	user.Username = c.PostForm("name")
	user.Email = c.PostForm("email")
	password := c.PostForm("password")

	if !isValidUsername(user.Username) {
		c.Redirect(http.StatusSeeOther, "/su/admin-panel?error=Invalid+username")
		return
	}

	// Validate email
	if !isValidEmail(user.Email) {
		c.Redirect(http.StatusSeeOther, "/su/admin-panel?error=Invalid+email")
		return
	}

	//Check if email already exists in the database
	existingUser := models.Credentials{}
	if err := configuration.DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		c.Redirect(http.StatusSeeOther, "/su/admin-panel?error=User+already+exists")
		return
	}

	//hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	// Create the new user
	if err := configuration.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	c.Redirect(http.StatusSeeOther, "/su/admin-panel?success=User+added+successfully")
}

func isValidUsername(username string) bool {
	// Username should contain only letters and should be between 4 and 20 characters
	regex := regexp.MustCompile("^[a-zA-Z]{4,20}$")
	return regex.MatchString(username)
}

func isValidEmail(email string) bool {
	// Use a simple regex pattern to check email format
	regex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return regex.MatchString(email)
}

// Search user
func SearchUser(c *gin.Context) {
	search_uname := c.Query("query")
	var temp_user []models.Credentials
	result := configuration.DB.Where("username ILIKE ?", "%"+search_uname+"%").Find(&temp_user)
	if result.Error != nil {
		c.Redirect(http.StatusSeeOther, "/su/admin-panel")

	} else {
		c.HTML(http.StatusOK, "adminpanel.html", gin.H{
			"temp_user": temp_user,
		})

	}

}

// POST request to edit user details based on the provided user ID
func EditUser(c *gin.Context) {
	id := c.Param("id")
	var user models.Credentials
	if err := configuration.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Update the user's details with the form data
	user.Username = c.PostForm("name")
	user.Email = c.PostForm("email")
	user.Password = c.PostForm("password")

	configuration.DB.Save(&user)
	c.Redirect(http.StatusSeeOther, "/su/admin-panel")
}

// request to delete a user based on the provided user ID
func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	var user models.Credentials
	if err := configuration.DB.First(&user, id).Error; err != nil {
		c.HTML(http.StatusNotFound, "login.html", gin.H{
			"error": "User not found",
		})
		return
	}
	// Check if the user being deleted is the currently logged-in user
	if user.Email == getEmailFromContext(c) {
		c.SetCookie("jwtToken", "", -1, "/", "", false, true)
		c.Redirect(http.StatusSeeOther, "/au/login")
	}
	configuration.DB.Delete(&user)
	c.Redirect(http.StatusSeeOther, "/su/admin-panel")
}

// Get the email from the context
func getEmailFromContext(c *gin.Context) string {
	if data, ok := c.Get("email"); ok {
		return data.(string)
	}
	return ""
}
