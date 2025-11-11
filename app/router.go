package app

import (
	"net/http"
	"os"
	"synk/gateway/app/controller"
	"synk/gateway/app/util"
)

func Router(service *Service) {
	aboutController := controller.NewAbout(service.DB)
	userController := controller.NewUsers(service.DB)

	http.HandleFunc("GET /about", aboutController.HandleAbout)
	http.HandleFunc("GET /users", userController.HandleShow)
	http.HandleFunc("POST /users/register", userController.HandleRegister)
	http.HandleFunc("POST /users/login", userController.HandleLogin)
	http.HandleFunc("GET /users/refresh", userController.HandleRefresh)
	http.HandleFunc("GET /users/check", userController.HandleCheck)

	util.Log("app running on port 8080 to " + os.Getenv("PORT"))

	err := http.ListenAndServe(":8080", controller.Cors(http.DefaultServeMux))
	if err != nil {
		util.Log("app failed on running on port 8080: " + err.Error())
	}
}
