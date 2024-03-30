package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("error loading godotenv")
	}

	r := http.NewServeMux()
	fs := http.FileServer(http.Dir("./static"))
	r.Handle("/static/", http.StripPrefix("/static/", fs))

	db, err := gorm.Open(sqlite.Open(os.Getenv("GODO_DB_PATH")), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&User{}, &Todo{})

	store := sessions.NewCookieStore([]byte(os.Getenv("GODO_COOKIE_STORE_SECRET")))

	stack := CreateMiddlewareStack(
		Logging,
	)

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t := newTemplate()

		session, _ := store.Get(r, "session")
		if session.Values["user"] != nil {
			var user User

			err := json.Unmarshal(session.Values["user"].([]byte), &user)
			if err != nil {
				fmt.Println("error unmarshalling user value")
			}

			todos, err := GetAll(user.ID, db)
			if err != nil {
				fmt.Println("error getting users todos")
			}

			t.Render(w, "index", newPageData(user, todos))
			return
		}

		var data interface{}

		t.Render(w, "index", data)
		return
	})

	r.HandleFunc("GET /auth/sign-in", func(w http.ResponseWriter, r *http.Request) {
		t := newTemplate()

		var data interface{}

		t.Render(w, "auth-form", data)
		return
	})

	r.HandleFunc("POST /auth/sign-in", func(w http.ResponseWriter, r *http.Request) {
		t := newTemplate()

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
		}

		email := r.Form.Get("email")
		password := r.Form.Get("password")

		var user User
		db.First(&user, "email = ?", email)

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		}

		session, _ := store.Get(r, "session")
		session.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			HttpOnly: true,
		}

		userBytes, err := json.Marshal(user)
		if err != nil {
			fmt.Println("error marshalling user value")
		}

		session.Values["user"] = userBytes

		err = session.Save(r, w)
		if err != nil {
			fmt.Println("error saving session: ", err)
		}

		todos, err := GetAll(user.ID, db)
		if err != nil {
			fmt.Println("error getting users todos")
		}

		t.Render(w, "index", newPageData(user, todos))
		return
	})

	r.HandleFunc("POST /auth/sign-out", func(w http.ResponseWriter, r *http.Request) {
		t := newTemplate()

		sess, _ := store.Get(r, "session")
		sess.Options.MaxAge = -1
		err := sess.Save(r, w)
		if err != nil {
			fmt.Println("error saving session")
		}

		var data interface{}

		t.Render(w, "index", data)
		return
	})

	s := http.Server{
		Addr:    ":8080",
		Handler: stack(r),
	}

	fmt.Println("Running server on localhost:8080")
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type Template struct {
	tmpl *template.Template
}

func newTemplate() *Template {
	return &Template{
		tmpl: template.Must(
			template.ParseGlob("template/*.html")),
	}
}

func (t *Template) Render(w io.Writer, name string, data interface{}) error {
	return t.tmpl.ExecuteTemplate(w, name, data)
}

type Middleware func(http.Handler) http.Handler

func CreateMiddlewareStack(xs ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(xs) - 1; i >= 0; i-- {
			x := xs[i]
			next = x(next)
		}
		return next
	}
}

type wrappedWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *wrappedWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
	w.statusCode = statusCode
}

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := &wrappedWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapped, r)

		log.Println(r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
	})
}

type PageData struct {
	User  User
	Todos []Todo
}

func newPageData(user User, todos []Todo) PageData {
	return PageData{
		User:  user,
		Todos: todos,
	}
}

type User struct {
	gorm.Model
	Name      string
	Email     string
	Password  string
	CreatedAt time.Time
	UpdatedAt *time.Time
	Todos     []Todo
}

type Todo struct {
	gorm.Model
	Title         string
	Completed     bool
	Description   *string
	DueDate       *time.Time
	CompletedDate *time.Time
	UserId        uint
}

func GetAll(userId uint, db *gorm.DB) ([]Todo, error) {
	var todos []Todo
	err := db.Model(&Todo{}).Find(&todos).Where("id = ?", userId).Error
	return todos, err
}
