package main

import (
    "fmt"
    "net/http"
    "os"
    "path/filepath"
    "strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
    filePath := r.URL.Query().Get("file")

    if filePath == "" {
        http.Error(w, "File path is required", http.StatusBadRequest)
        return
    }

    // Rentan Path Traversal
    data, err := os.ReadFile(filePath)
    if err != nil {
        http.Error(w, "Error reading file: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "text/plain")
    w.Write(data)
}

func main() {
    http.HandleFunc("/read", handler)
    fmt.Println("Server running at http://localhost:8080")
    http.ListenAndServe(":8080", nil)
}
