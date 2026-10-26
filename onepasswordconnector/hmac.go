package onepasswordconnector

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const maxSignatureAge = 5 * time.Minute

// maxBodyBytes caps what an unverified caller can make the connector buffer. The signature covers
// the body, so it can only be checked once the whole body is read; without a cap, anyone who can
// reach the connector exhausts its memory with one large request.
const maxBodyBytes = 1 << 20

// VerifySignature rejects requests not signed by Opal. It must byte-match Opal's request signer:
// HMAC-SHA256 hex over "v0:" + timestamp + ":" + whitespace-trimmed body, with an empty body signed
// as "{}".
func VerifySignature(secret string, now func() time.Time) gin.HandlerFunc {
	return func(c *gin.Context) {
		timestamp := c.GetHeader("X-Opal-Request-Timestamp")
		signature := c.GetHeader("X-Opal-Signature")
		if timestamp == "" || signature == "" {
			abortUnauthorized(c, "missing signature headers")
			return
		}
		seconds, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil || now().Sub(time.Unix(seconds, 0)).Abs() > maxSignatureAge {
			abortUnauthorized(c, "stale or invalid timestamp")
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				abort(c, http.StatusRequestEntityTooLarge, "request body is too large")
				return
			}
			abortUnauthorized(c, "unreadable body")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		if !hmac.Equal([]byte(Sign(secret, timestamp, body)), []byte(signature)) {
			abortUnauthorized(c, "invalid signature")
			return
		}
		c.Next()
	}
}

// Sign computes the signature Opal sends for body at timestamp.
func Sign(secret, timestamp string, body []byte) string {
	payload := strings.TrimSpace(string(body))
	if payload == "" {
		payload = "{}"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + timestamp + ":" + payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func abortUnauthorized(c *gin.Context, message string) {
	abort(c, http.StatusUnauthorized, message)
}

func abort(c *gin.Context, status int, message string) {
	c.AbortWithStatusJSON(status, Error{Code: int32(status), Message: message})
}
