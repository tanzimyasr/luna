package middleware

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"luna-backend/api/internal/util"
	"luna-backend/auth"
	"luna-backend/config"
	"luna-backend/crypto"
	"luna-backend/db"
	"luna-backend/errors"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mileusna/useragent"
	"github.com/sirupsen/logrus"
)

func RequestSetup(timeout time.Duration, database *db.Database, withTransaction bool, config *config.CommonConfig, logger *logrus.Entry) gin.HandlerFunc {
	return func(c *gin.Context) {
		responseStatus := http.StatusOK
		var responseRaw []byte
		var responseRawType string
		var responseMsg *gin.H
		var responseFileName string
		var responseFileBody []byte
		var responseErr *errors.ErrorTrace
		var responseWarns []*errors.ErrorTrace

		// Final response sent at the end of the execution.
		defer func() {
			c.Header("Access-Control-Allow-Origin", config.Env.PUBLIC_URL)

			if responseFileBody != nil {
				c.Header("Content-Disposition", "attachment; filename="+responseFileName)
				c.Header("Content-Type", "application/text/plain")
				c.Header("Accept-Length", fmt.Sprintf("%d", len(responseFileBody)))
				var err error
				if c.Request.Method != http.MethodHead {
					_, err = c.Writer.Write(responseFileBody) // TODO: it would be nice if we could prevent the body from being fetched in first place
				}

				if err != nil {
					responseErr = errors.New().Status(http.StatusInternalServerError).
						AddErr(errors.LvlDebug, err).
						AltStr(errors.LvlPlain, "Could not download file")
				} else {
					return
				}
			}

			if responseErr != nil {
				logger.Error(responseErr.Serialize(errors.LvlDebug))
				c.AbortWithStatusJSON(responseErr.GetStatus(), &gin.H{"error": responseErr.Serialize(config.LoggingVerbosity())})
				return
			}

			if responseRaw != nil {
				c.Data(responseStatus, responseRawType, responseRaw)
				return
			}

			if responseMsg == nil {
				responseMsg = &gin.H{"status": "ok"}
			}

			if len(responseWarns) > 0 {
				warnStrs := make([]string, len(responseWarns))
				for i, warn := range responseWarns {
					logger.Warn(warn.Serialize(errors.LvlDebug))
					warnStrs[i] = warn.Serialize(config.LoggingVerbosity())
				}

				(*responseMsg)["warnings"] = warnStrs
			}

			c.JSON(responseStatus, *responseMsg)
		}()

		// Timeout to be used by the handler and all its long-running functions (database queries, network request, ...)
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		// Timeout to be used by the database transaction (longer than usual timeout to allow for rollback)
		dbCtx, dbCancel := context.WithTimeout(c.Request.Context(), timeout+10*time.Second)
		defer dbCancel()

		// If the request uses the database at all, we create a transaction for it.
		var tx *db.Transaction
		if withTransaction {
			tx, responseErr = database.BeginTransaction(dbCtx)
			if responseErr != nil {
				return
			}
		}

		// The handler will report back with a response body or an error trace
		responseChan := make(chan *util.Response)
		errChan := make(chan *errors.ErrorTrace)
		warnChan := make(chan *errors.ErrorTrace)

		// Pass important variables to the handler
		c.Set("transaction", tx)
		c.Set("config", config)
		c.Set("logger", logger)
		c.Set("context", ctx)

		// Pass important variables to the handler
		c.Set("transaction", tx)
		c.Set("config", config)
		c.Set("logger", logger)
		c.Set("context", ctx)

		c.Set("handlerUtil", &util.HandlerUtility{
			Config:       config,
			Logger:       logger,
			Tx:           tx,
			Context:      ctx,
			GinContext:   c,
			ResponseChan: responseChan,
			ErrChan:      errChan,
			WarnChan:     warnChan,
		})

		// Pass the execution on to the next middleware or the handler
		go func() {
			c.Next()
		}()

		// Gather warnings until we are done
		go func() {
			for {
				select {
				case warn := <-warnChan:
					responseWarns = append(responseWarns, warn)
				case <-ctx.Done():
					return
				}
			}
		}()

		// Wait until we either get a response, an error, or the time for the request expires
		select {
		// In case of a response
		case response := <-responseChan:
			responseStatus = response.GetStatus()
			responseRaw = response.GetRaw()
			responseRawType = response.GetRawType()
			responseMsg = response.GetMsg()
			responseFile := response.GetFile()

			if responseFile != nil {
				responseFileName = responseFile.GetName(tx.Queries())
				responseFileBody, responseErr = responseFile.GetBytes(tx.Queries())
				if responseErr != nil {
					return
				}
			}

			// Commit if the database was used
			if withTransaction {
				responseErr = tx.Commit(logger)
				if responseErr != nil {
					return
				}
			}

		// In case of a reported error
		case responseErr = <-errChan:
			// Rollback if the database was used
			if withTransaction {
				rollbackErr := tx.Rollback(logger)
				if rollbackErr != nil {
					logger.Error(rollbackErr.Serialize(errors.LvlDebug))
				}
			}

		// In case of a timeout or other unexpected error
		case <-ctx.Done():
			// Wait for a small time amount to see if we get a more detailed error about what exactly timed out
			select {
			case responseErr = <-errChan:
			case <-time.After(100 * time.Millisecond):
			}

			if responseErr == nil {
				responseErr = errors.New()
			}

			// Rollback if the database was used
			if withTransaction {
				rollbackErr := tx.Rollback(logger)
				if rollbackErr != nil {
					logger.Error(rollbackErr.Serialize(errors.LvlDebug))
				}
			}

			if ctx.Err() == context.DeadlineExceeded {
				// Would prefer to use StatusRequestTimeout, but then the browser keeps retrying indefinitely
				responseErr.Status(http.StatusGatewayTimeout).
					Append(errors.LvlWordy, "Request timed out after %v seconds", timeout.Seconds()).
					AltStr(errors.LvlBroad, "Request timed out")
			} else {
				responseErr.
					Append(errors.LvlBroad, "Request failed")
			}
		}
	}
}

// Error messages must be kept intentionally vague even in higher verbosity levels,
// to avoid the creation of an oracle.
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		u := util.GetUtil(c)

		cookieToken, cookieErr := c.Cookie("token")
		gotCookie := cookieErr == nil && cookieToken != ""
		bearerToken, bearerErr := util.GetBearerToken(c)
		gotBearer := bearerErr == nil && bearerToken != ""

		if !gotCookie && !gotBearer {
			u.Error(errors.New().Status(http.StatusUnauthorized).
				Append(errors.LvlWordy, "Missing token"))
			c.Abort()
			return
		}

		var token string
		if gotBearer {
			token = bearerToken
		} else if gotCookie {
			token = cookieToken
		}

		// Parse the token => Verifies that it was signed by the server
		parsedToken, tr := auth.ParseToken(u.Config, token)
		if tr != nil {
			u.Error(tr)
			c.Abort()
			return
		}

		// Find the session in the database => Verifies that the session has not been revoked and that the user exists
		session, tr := u.Tx.Queries().GetSessionAndUpdateLastSeen(parsedToken.UserId, parsedToken.SessionId, net.ParseIP(c.ClientIP()))
		if tr != nil {
			u.Error(tr)
			c.Abort()
			return
		}

		// Check if the secret from the token hashes to the same value as the one in the database.
		// This is one line of defense against forged tokens.
		secret, err := base64.StdEncoding.DecodeString(parsedToken.Secret)
		if err != nil {
			u.Error(errors.New().Status(http.StatusUnauthorized).
				AddErr(errors.LvlDebug, err).
				Append(errors.LvlDebug, "Could not decode secret from token").
				Append(errors.LvlPlain, "Session expired"),
			)
			c.Abort()
			return
		}
		actualHash := crypto.GetSha256Hash(secret)
		if !bytes.Equal(actualHash, session.SecretHash) {
			u.Error(errors.New().Status(http.StatusUnauthorized).
				Append(errors.LvlDebug, "Token secret value produces incorrect hash value").
				Append(errors.LvlPlain, "Session expired"),
			)
			c.Abort()
			return
		}

		// Check if the user agent matches the one used to create the session
		// This is not a 100% guarantee that the token was not stolen, but it is a good first line of defense
		// This is disabled for API requests and for loading data from +page.ts or +layout.ts in Svelte.
		// While an attacker could just set their user agent to "FrontendLoad",
		// this is not that much easier than setting the correct user agent in first place.
		if !(session.IsApi || (c.Request.UserAgent() == "FrontendLoad" && (c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead))) {
			// Compare the user agents => Verifies that the token was not stolen and used from another device (not a 100% guarantee)
			associatedUserAgent := useragent.Parse(session.UserAgent)
			currentUserAgent := useragent.Parse(c.Request.UserAgent())

			osMatch := associatedUserAgent.OS == currentUserAgent.OS
			nameMatch := associatedUserAgent.Name == currentUserAgent.Name
			deviceMatch := associatedUserAgent.Device == currentUserAgent.Device

			if !osMatch || !nameMatch || !deviceMatch || (session.IsShortLived && associatedUserAgent.String != currentUserAgent.String) {
				u.Error(errors.New().Status(http.StatusUnauthorized).
					Append(errors.LvlDebug, "Expected %s, but got %s",
						fmt.Sprintf("%s %s %s", associatedUserAgent.OS, associatedUserAgent.Name, associatedUserAgent.Device),
						fmt.Sprintf("%s %s %s", currentUserAgent.OS, currentUserAgent.Name, currentUserAgent.Device)).
					Append(errors.LvlDebug, "User agent mismatch").
					Append(errors.LvlPlain, "Session expired"),
				)

				u.Config.TokenInvalidationChannel <- session

				c.Abort()
				return
			}
		}

		c.Set("user_id", parsedToken.UserId)
		c.Set("session_id", parsedToken.SessionId)

		c.Next()
	}
}

func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		u := util.GetUtil(c)
		userId := util.GetUserId(c)

		isAdmin, err := u.Tx.Queries().IsAdmin(userId)
		if err != nil {
			u.Error(err)
			c.Abort()
			return
		}

		if !isAdmin {
			u.Error(errors.New().Status(http.StatusForbidden).
				Append(errors.LvlPlain, "You must be an administrator to do this"))
			c.Abort()
			return
		}

		c.Next()
	}
}

func DynamicThrottle(throttle *util.Throttle) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := util.GetUtil(c)

		ip := net.ParseIP(c.ClientIP()).String()

		failCount := throttle.GetFailedAttempts(ip)
		if failCount > 50 {
			u.Logger.Warnf("IP %s has failed %d times in the last minute, aborting...", ip, failCount)
			u.Error(errors.New().Status(http.StatusTooManyRequests).
				Append(errors.LvlPlain, "Too many failed requests from this IP address"),
			)
			c.Abort()
		} else if failCount > 15 {
			u.Logger.Warnf("IP %s has failed %d times in the last minute, throttling...", ip, failCount)
			time.Sleep(5 * time.Second)
		} else if failCount > 10 {
			u.Logger.Warnf("IP %s has failed %d times in the last minute, throttling...", ip, failCount)
			time.Sleep(1 * time.Second)
		} else if failCount > 5 {
			u.Logger.Warnf("IP %s has failed %d times in the last minute, throttling...", ip, failCount)
			time.Sleep(100 * time.Millisecond)
		}

		c.Next()

		// Check for errors
		if _, errored := c.Get("error"); !errored {
			// Reset the number of failures if the request was successful
			throttle.RecordSuccessfulAttempt(ip)
		} else {
			// Increment the number of failures
			throttle.RecordFailedAttempt(ip)
		}
	}
}
