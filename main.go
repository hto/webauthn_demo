package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo"
	"github.com/mvndaai/webauthn"
	scribble "github.com/nanobox-io/golang-scribble"
)

var port = flag.String("port", ":8080", "Port the server starts on")
var origin = flag.String("origin", "http://localhost:8080", "Origin used in verification")
var timeout = flag.Int("timeout", 6000, "Time till auth timeout in ms")

var db *scribble.Driver

const dbColletion = "users"

type (
	dbDevice struct {
		Name         string `json:"name"`
		Origin       string `json:"origin"`
		Challenge    []byte `json:"challenge"`
		CredentialID string `json:"credentialId"`
	}

	dbItem struct {
		User    webauthn.UserEntity  `json:"user"`
		Devices map[string]*dbDevice `json:"devices"`
	}
)

func main() {
	flag.Parse()
	initDatabase()

	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if he, ok := err.(*echo.HTTPError); ok {
			if he.Code == http.StatusNotFound {
				c.Logger().Error("route not found: ", c.Request().URL.String())
				c.NoContent(he.Code)
				return
			}
			c.String(he.Code, fmt.Sprint(he.Message))
		} else {
			c.String(http.StatusInternalServerError, err.Error())
		}
		c.Logger().Error(err)
	}

	e.GET("/", indexHandle)

	e.POST("/registration/start", startRegistration)
	e.POST("/registration/finish", finishRegistration)

	e.POST("/authentication/start", startAuthentication)
	e.POST("/authentication/finish", finishAuthentication)

	e.Logger.Fatal(e.Start(*port))
}

func indexHandle(c echo.Context) error {
	return c.File("index.html")
}

type (
	startRegistrationResponse struct {
		DeviceName string              `json:"deviceName"`
		Origin     string              `json:"origin"`
		User       webauthn.UserEntity `json:"user"`
	}
)

func startRegistration(c echo.Context) error {
	b := startRegistrationResponse{}
	if err := json.NewDecoder(c.Request().Body).Decode(&b); err != nil {
		return err
	}
	if b.User.Name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "username required")
	}

	log.Println("Starting registation for:", b.User.Name)
	chal, err := webauthn.NewChallenge()
	if err != nil {
		return err
	}

	entry := dbItem{}

	err = db.Read(dbColletion, b.User.Name, &entry)
	if err != nil {
		// This error should happen unless adding a device to an existing user
		if !strings.HasPrefix(err.Error(), "stat") {
			return err
		}
		entry.User.ID = []byte(uuid.New().String())
		entry.User.Name = b.User.Name
	}
	entry.User.DisplayName = b.User.DisplayName

	if entry.Devices == nil {
		entry.Devices = map[string]*dbDevice{}
	}
	entry.Devices[b.DeviceName] = &dbDevice{
		Name:      b.DeviceName,
		Origin:    b.Origin,
		Challenge: chal,
	}

	log.Printf("user %#v\n", entry.User)
	err = db.Write(dbColletion, b.User.Name, entry)
	if err != nil {
		return err
	}
	log.Println("def")

	r := webauthn.RegistrationParts{
		PublicKey: webauthn.PublicKeyCredentialOptions{
			Challenge: chal,
			RP: webauthn.RpEntity{
				Name: "mvndaai-webauth-demo",
			},
			PubKeyCredParams: []webauthn.Parameters{
				webauthn.Parameters{
					Type: webauthn.PublicKeyCredentialTypePublicKey,
					Alg:  -7,
				},
			},
			Timeout:     500000,
			User:        entry.User,
			Attestation: "direct",
		},
	}

	return c.JSON(http.StatusCreated, r)
}

type (
	finishResponse struct {
		webauthn.PublicKeyCredential
		User       webauthn.UserEntity `json:"user"`
		DeviceName string              `json:"deviceName"`
	}
)

func finishRegistration(c echo.Context) error {
	b := finishResponse{}
	if err := c.Bind(&b); err != nil {
		return err
	}

	entry := dbItem{}
	err := db.Read(dbColletion, b.User.Name, &entry)
	if err != nil {
		return err
	}

	log.Printf("entry.Devices[b.deviceName].Challenge %s %#v\n", b.DeviceName, entry.Devices)

	err = webauthn.ValidateRegistration(b.PublicKeyCredential, entry.Devices[b.DeviceName].Challenge, *origin, false)
	if err != nil {
		delete(entry.Devices, b.DeviceName)
		log.Println("Registation Validation failed", err)
	}

	device := entry.Devices[b.DeviceName]
	device.Challenge = nil
	device.CredentialID = string(b.RawID)
	entry.Devices[b.DeviceName] = device

	err = db.Write(dbColletion, b.User.Name, entry)
	if err != nil {
		return err
	}

	return c.NoContent(http.StatusCreated)
}

type (
	startAuthResponse struct {
		Challenge    string              `json:"challenge"`
		CredentialID string              `json:"credentialId"`
		DeviceName   string              `json:"deviceName"`
		User         webauthn.UserEntity `json:"user"`
	}
)

func startAuthentication(c echo.Context) error {
	b := startAuthResponse{}
	if err := c.Bind(&b); err != nil {
		return err
	}
	log.Println("startAuthentication", b)
	entry := dbItem{}
	err := db.Read(dbColletion, b.User.Name, &entry)
	if err != nil {
		return err
	}
	log.Println("entry", entry)

	chal, err := webauthn.NewChallenge()
	if err != nil {
		return err
	}

	device := entry.Devices[b.DeviceName]
	device.Challenge = chal
	entry.Devices[b.DeviceName] = device

	err = db.Write(dbColletion, b.User.Name, entry)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusCreated, startAuthResponse{
		Challenge:    base64Encode(chal),
		CredentialID: device.CredentialID,
	})
}

func finishAuthentication(c echo.Context) error {

	b := finishResponse{}
	if err := c.Bind(&b); err != nil {
		return err
	}
	log.Println("finishAuthentication", b)

	entry := dbItem{}
	err := db.Read(dbColletion, b.User.Name, &entry)
	if err != nil {
		return err
	}
	log.Println("entry", entry)
	chal := entry.Devices[b.DeviceName].Challenge

	// Cleanup challenge
	device := entry.Devices[b.DeviceName]
	device.Challenge = nil
	entry.Devices[b.DeviceName] = device
	err = db.Write(dbColletion, b.User.Name, entry)
	if err != nil {
		return err
	}

	log.Println("b.PublicKeyCredential, chal, *origin, string(entry.User.ID)", b.PublicKeyCredential, chal, *origin, string(entry.User.ID))
	err = webauthn.ValidateAuthentication(b.PublicKeyCredential, chal, *origin, string(entry.User.ID))
	if err != nil {
		return err
	}

	return c.NoContent(http.StatusCreated)
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func initDatabase() {
	var err error
	db, err = scribble.New("data", &scribble.Options{})
	if err != nil {
		panic(err)
	}
}
