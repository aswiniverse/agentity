package api

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
)

//go:embed web
var webFS embed.FS

func registerAdminRoutes(r chi.Router) {
	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		panic("admin UI: failed to sub web fs: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(webRoot))
	r.Handle("/admin", http.RedirectHandler("/admin/", http.StatusMovedPermanently))
	r.Handle("/admin/*", http.StripPrefix("/admin", fileServer))
}
