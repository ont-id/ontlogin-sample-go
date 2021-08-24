package auth

import (
	"context"
	"fmt"
	"net/http"

	. "ontlogin-sample/jwt"
)

var userCtxKey = &contextKey{"user"}

type contextKey struct {
	name string
}

func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")

			// Allow unauthenticated users in
			if header == "" {
				next.ServeHTTP(w, r)
				//http.Error(w, "need login first", http.StatusForbidden)
				return
			}

			//validate jwt token
			tokenStr := header
			did, err := ParseToken(tokenStr)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintln(w, `{"message":"invalid jwt token, please login again"}`)
				//http.Error(w, `{"message":"invalid jwt token, please login again"}`, http.StatusForbidden)
				return
			}

			// put it in context
			ctx := context.WithValue(r.Context(), userCtxKey, did)

			// and call the next with our new context
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// ForContext finds the user from the context. REQUIRES Middleware to have run.
func ForContext(ctx context.Context) string {
	raw, _ := ctx.Value(userCtxKey).(string)
	return raw
}

func CheckLogin(ctx context.Context) error {
	if did := ForContext(ctx); did == "" {
		return fmt.Errorf("did is not match,please login first")
	}
	return nil
}
