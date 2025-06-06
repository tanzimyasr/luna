package queries

import (
	"luna-backend/errors"
	"luna-backend/types"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

func (q *Queries) InsertSession(session *types.Session) *errors.ErrorTrace {
	// Session object does not have an ID or timestamp yet
	// These are generated by the database and updated in the session object

	query := `
		INSERT INTO sessions (userid, user_agent, initial_ip_address, last_ip_address, is_short_lived, is_api, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING sessionid, created_at, last_seen;	
	`

	err := q.Tx.
		QueryRow(
			q.Context,
			query,
			session.UserId.UUID(),
			session.UserAgent,
			session.InitialIpAddress,
			session.LastIpAddress,
			session.IsShortLived,
			session.IsApi,
			session.SecretHash,
		).Scan(&session.SessionId, &session.CreatedAt, &session.LastSeen)

	if err != nil {
		return errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlWordy, "Could not insert session").
			Append(errors.LvlPlain, "Database error")
	}

	return nil
}

func (q *Queries) UpdateSession(session *types.Session) *errors.ErrorTrace {
	query := `
		UPDATE sessions
		SET user_agent = $1
		WHERE sessionid = $2;
	`

	_, err := q.Tx.Exec(q.Context, query, session.UserAgent, session.SessionId)
	switch err {
	case nil:
		return nil
	case pgx.ErrNoRows:
		return errors.New().Status(http.StatusNotFound).
			Append(errors.LvlPlain, "Session not found")
	default:
		return errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not execute query").
			Append(errors.LvlWordy, "Could not update session").
			Append(errors.LvlPlain, "Database error")
	}
}

func (q *Queries) GetSession(userid types.ID, sessionId types.ID) (*types.Session, *errors.ErrorTrace) {
	query := `
		SELECT *
		FROM sessions
		WHERE userid = $1 AND sessionid = $2;
	`

	rows, err := q.Tx.Query(q.Context, query, userid, sessionId)
	if err != nil {
		return nil, errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not execute query").
			Append(errors.LvlWordy, "Could not get session").
			Append(errors.LvlPlain, "Database error")
	}

	session, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[types.Session])
	switch err {
	case nil:
		break
	case pgx.ErrNoRows:
		return nil, errors.New().Status(http.StatusUnauthorized).
			Append(errors.LvlPlain, "Session expired")
	default:
		return nil, errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not scan session").
			Append(errors.LvlWordy, "Could not get session").
			Append(errors.LvlPlain, "Database error")
	}

	return &session, nil
}

func (q *Queries) GetSessionAndUpdateLastSeen(userId types.ID, sessionId types.ID, ipAddress net.IP) (*types.Session, *errors.ErrorTrace) {
	query := `
		UPDATE sessions
		SET last_seen = NOW(), last_ip_address = $3
		WHERE userid = $1 AND sessionid = $2
		RETURNING *;
	`

	rows, err := q.Tx.Query(q.Context, query, userId, sessionId, ipAddress)
	if err != nil {
		return nil, errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not execute query").
			Append(errors.LvlWordy, "Could not get or update session").
			Append(errors.LvlPlain, "Database error")
	}

	session, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[types.Session])
	switch err {
	case nil:
		break
	case pgx.ErrNoRows:
		return nil, errors.New().Status(http.StatusUnauthorized).
			Append(errors.LvlPlain, "Session expired")
	default:
		return nil, errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not scan session").
			Append(errors.LvlWordy, "Could not get or update session").
			Append(errors.LvlPlain, "Database error")
	}

	return &session, nil
}

func (q *Queries) GetSessions(userId types.ID) ([]types.Session, *errors.ErrorTrace) {
	query := `
		SELECT *
		FROM sessions
		WHERE userid = $1
		ORDER BY last_seen DESC;
	`

	rows, err := q.Tx.Query(q.Context, query, userId)
	if err != nil {
		return nil, errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not execute query").
			Append(errors.LvlWordy, "Could not get sessions").
			Append(errors.LvlPlain, "Database error")
	}

	sessions, err := pgx.CollectRows(rows, pgx.RowToStructByName[types.Session])
	if err != nil {
		return nil, errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not scan sessions").
			Append(errors.LvlWordy, "Could not get sessions").
			Append(errors.LvlPlain, "Database error")
	}

	return sessions, nil
}

func (q *Queries) DeleteSession(userId types.ID, sessionId types.ID) *errors.ErrorTrace {
	query := `
		DELETE FROM sessions
		WHERE userid = $1 AND sessionid = $2;
	`

	_, err := q.Tx.Exec(q.Context, query, userId, sessionId)
	if err != nil {
		return errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not execute query").
			Append(errors.LvlWordy, "Could not delete session").
			Append(errors.LvlPlain, "Database error")
	}
	return nil
}

func (q *Queries) DeleteSessions(userid types.ID) *errors.ErrorTrace {
	query := `
		DELETE FROM sessions
		WHERE userid = $1;
	`

	_, err := q.Tx.Exec(q.Context, query, userid)
	if err != nil {
		return errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not execute query").
			Append(errors.LvlWordy, "Could not delete sessions").
			Append(errors.LvlPlain, "Database error")
	}
	return nil
}

func (q *Queries) DeleteUserSessions(userid types.ID) *errors.ErrorTrace {
	query := `
		DELETE FROM sessions
		WHERE userid = $1
		AND is_api = false;
	`

	_, err := q.Tx.Exec(q.Context, query, userid)
	if err != nil {
		return errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not execute query").
			Append(errors.LvlWordy, "Could not delete sessions").
			Append(errors.LvlPlain, "Database error")
	}
	return nil
}

func (q *Queries) DeleteApiSessions(userid types.ID) *errors.ErrorTrace {
	query := `
		DELETE FROM sessions
		WHERE userid = $1
		AND is_api = true;
	`

	_, err := q.Tx.Exec(q.Context, query, userid)
	if err != nil {
		return errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not execute query").
			Append(errors.LvlWordy, "Could not delete sessions").
			Append(errors.LvlPlain, "Database error")
	}
	return nil
}

func (q *Queries) DeleteExpiredSessions(deleteBefore time.Time, shortLived bool) *errors.ErrorTrace {
	query := `
		DELETE FROM sessions
		WHERE last_seen < $1
		AND is_short_lived = $2
		AND is_api = false;
	`

	_, err := q.Tx.Exec(q.Context, query, deleteBefore, shortLived)
	if err != nil {
		return errors.New().Status(http.StatusInternalServerError).
			AddErr(errors.LvlDebug, err).
			Append(errors.LvlDebug, "Could not execute query").
			Append(errors.LvlWordy, "Could not delete expired sessions").
			Append(errors.LvlPlain, "Database error")
	}
	return nil
}
