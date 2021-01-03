package main

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/theykk/2fa-auth/cookie"
	"github.com/theykk/2fa-go"
	"html/template"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"
)

// ? Version of build
var (
	Version = "dev"
)

var port = flag.String("port", getenv("PORT", strconv.Itoa(8080)), "Port to listen on for HTTP")
var printVersion = flag.Bool("v", false, "Print version")
var help = flag.Bool("help", false, "Get Help")
var listen = flag.String("listen", getenv("LISTEN", "0.0.0.0"), "IPv4 address to listen on")
var cookieDomain = flag.String("cookie-domain", "", "IPv4 address to listen on")

func init() {

	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *printVersion {
		fmt.Print(Version)
		os.Exit(0)
	}

	if Version == "dev" {
		log.SetFormatter(&log.JSONFormatter{
			PrettyPrint: true,
		})
	} else {
		log.SetFormatter(&log.JSONFormatter{})
	}
	log.SetReportCaller(true)
}
func main() {
	log.Printf("Init 2FA-AUTH %s", Version)

	secretAuth := getenv("AUTH_2FA_SECRET", "")
	if secretAuth == "" {
		log.Fatal("2FA secret not set")
		return
	}
	cookieSecret := getenv("AUTH_COOKIE_SECRET", "")
	if cookieSecret == "" {
		log.Fatal("Cookie Secret secret not set")
		return
	}



	// ? Create http server
	router := mux.NewRouter()

	router.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"version": Version})
	}).Methods("GET")

	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "OK")
	}).Methods("GET")

	router.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		// ? Check auth cookie is exist , if not return Http Unauthorized response
		cookieAuth, err := r.Cookie("_auth_2fa")
		if err != nil  || cookieAuth == nil {
			log.Error("Can't get cookie")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if len(cookieAuth.Value) <= 0 {
			log.Error("Cookie is empty")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// ? Validate cookie
		_,_,ok := cookie.Validate(cookieAuth,"sa",time.Duration(168)*time.Hour)
		if !ok {
			log.Error("cookie signature not valid")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		return
	}).Methods("GET")

	// * https://2fa.theykk.com/start?rd=https://terminal.theykk.com/sea1
	router.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("rd")

		parsedTemplate, _ := template.ParseFiles("2fa.html")
		err := parsedTemplate.Execute(w, struct {
			RedirectUrl string
		}{
			RedirectUrl: redirect,
		})
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}

		// ? Response 2fa form html
	}).Methods("GET")

	router.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()
		authCode := r.Form.Get("code")
		redirectUrl := r.Form.Get("redirect")

		// ? Get 2FA Auth code from secret
		secretEncoded := base32.StdEncoding.EncodeToString([]byte(secretAuth))
		authToken := go2fa.GetTOTPToken(secretEncoded)

		if authCode == authToken {
			// ? Set cookie
			cookieVal , err := cookie.SignedValue(secretAuth, "_auth_2fa", []byte("sea"), time.Now())
			if err != nil {
				log.Error("Can't sign cookie")
				w.WriteHeader(http.StatusInternalServerError)
			}

			http.SetCookie(w, &http.Cookie{
				Name: "_auth_2fa",
				Value: cookieVal,
				HttpOnly: true,
				Secure: true,
				Expires: time.Now().Add(time.Duration(168)*time.Hour),
				Domain: *cookieDomain,
			})

			// ? Redirect to url
			http.Redirect(w,r,redirectUrl,http.StatusFound)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}).Methods("POST")

	router.HandleFunc("/deny", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}).Methods("GET")

	// ? listen and serve on default 0.0.0.0:8080
	srv := &http.Server{
		Handler: tracing()(logging()(router)),
		Addr:    *listen + ":" + *port,
		// ! Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Info("Serve at: ", *listen+":"+*port)

	errServe := srv.ListenAndServe()
	if errServe != nil {
		log.Fatalf("Server err %s", errServe)
	}
}
type key int

const (
	requestIDKey key = 0
)

// ? logging logs http request with http details such as  header , userAgent
func logging() func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			requestID, ok := r.Context().Value(requestIDKey).(string)
			if !ok {
				requestID = "unknown"
			}

			hostname, err := os.Hostname()
			if err != nil {
				hostname = "unknow"
			}

			start := time.Now()

			// ? Execute next htpp middleware and calculate execution time
			next.ServeHTTP(w, r)

			stop := time.Since(start)
			latency := int(math.Ceil(float64(stop.Nanoseconds()) / 1000000.0))

			// ? Try to get user ip
			IPAddress := r.Header.Get("X-Real-Ip")
			if IPAddress == "" {
				IPAddress = r.Header.Get("X-Forwarded-For")
			}
			if IPAddress == "" {
				IPAddress = r.RemoteAddr
			}

			log.WithFields(log.Fields{
				"hostname":  hostname,
				"requestID": requestID,
				"latency":   latency, // time to process
				"clientIP":  IPAddress,
				"method":    r.Method,
				"path":      r.URL.Path,
				"header":    r.Header,
				"referer":   r.Referer(),
				"userAgent": r.UserAgent(),
			}).Info("Request")
		})
	}
}

// ? tracing trace http request with "X-Request-Id"
func tracing() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = strconv.FormatInt(time.Now().UnixNano(), 10)
			}
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)
			w.Header().Set("X-Request-Id", requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}
