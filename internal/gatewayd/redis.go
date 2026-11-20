package gatewayd

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	redisDialTimeout = 3 * time.Second
	redisReplyLimit  = 128 * 1024
)

var (
	errRedisUnavailable = errors.New("redis unavailable")
	// errLockLost reports that a lock-conditional write found the lock gone or
	// owned by someone else.
	errLockLost = errors.New("redis lock lost")
	// errStateChanged reports that a state-conditional write found the record
	// different from the one the caller meant to replace or remove.
	errStateChanged = errors.New("redis record changed")
)

// publicationKey is the sibling key holding the publication marker of the
// record at key. Legacy readers never look at it.
func publicationKey(key string) string { return key + ":gatewayd:publication" }

// markerTolerance is how far a marker's recorded expiry may differ from the
// record's current server-side expiry and still count as describing it. A
// different writer replaces the record and moves the expiry by far more.
const markerTolerance = 50 * time.Millisecond

// RedisStore is the narrow capability set required by the issuer. The
// read-only KIS paths retain their separate GET-only client.
type RedisStore interface {
	Get(ctx context.Context, key string) (value string, present bool, err error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	CompareAndDelete(ctx context.Context, key, value string) error
	// SetIfLockHeld stores key=value with an EX TTL only while lockKey still
	// holds lockValue, so an issuer whose lease expired cannot overwrite a
	// successor's publication. A non-empty publication is recorded, in the same
	// atomic step, as a marker bound to the new record and its expiry; it lets a
	// reader tell this publication from a later one with identical bytes. It
	// returns errLockLost when the lock is not held.
	SetIfLockHeld(ctx context.Context, lockKey, lockValue, key, value string, ttl time.Duration, publication string) error
	// ExtendLockIfHeld resets lockKey's TTL to ttl only while it holds lockValue.
	ExtendLockIfHeld(ctx context.Context, lockKey, lockValue string, ttl time.Duration) error
	// WithdrawIfLockHeld deletes key only while lockKey holds lockValue and key
	// still holds expected. errLockLost / errStateChanged report which check failed.
	WithdrawIfLockHeld(ctx context.Context, lockKey, lockValue, key, expected string) error
}

// RedisClient is a small RESP client for the issuer's GET, SET, SET NX EX,
// and ownership-checked lock release. It never includes the Redis URL or a
// command payload in an error.
type RedisClient struct {
	scheme   string
	address  string
	server   string
	username string
	password string
	database int
}

// NewRedisClient parses redis:// and rediss:// URLs without allowing query or
// fragment options that could widen its behavior.
func NewRedisClient(rawURL string) (*RedisClient, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") ||
		parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errRedisUnavailable
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, errRedisUnavailable
	}
	port := parsed.Port()
	if port == "" {
		port = "6379"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errRedisUnavailable
	}
	database, err := parseRedisDatabase(parsed.Path)
	if err != nil {
		return nil, errRedisUnavailable
	}
	client := &RedisClient{
		scheme:   parsed.Scheme,
		address:  net.JoinHostPort(host, port),
		server:   host,
		database: database,
	}
	if parsed.User != nil {
		password, hasPassword := parsed.User.Password()
		if parsed.User.Username() != "" && !hasPassword {
			return nil, errRedisUnavailable
		}
		client.username = parsed.User.Username()
		client.password = password
	}
	return client, nil
}

func parseRedisDatabase(path string) (int, error) {
	if path == "" || path == "/" {
		return 0, nil
	}
	if !strings.HasPrefix(path, "/") || strings.Count(path, "/") != 1 {
		return 0, errors.New("invalid redis database")
	}
	database, err := strconv.Atoi(strings.TrimPrefix(path, "/"))
	if err != nil || database < 0 || database > 65535 {
		return 0, errors.New("invalid redis database")
	}
	return database, nil
}

// Get loads one cache value. Missing values are not an error.
func (client *RedisClient) Get(ctx context.Context, key string) (string, bool, error) {
	reply, err := client.execute(ctx, "GET", key)
	if err != nil {
		return "", false, errRedisUnavailable
	}
	if reply.nilValue {
		return "", false, nil
	}
	if reply.kind != '$' {
		return "", false, errRedisUnavailable
	}
	return reply.text, true, nil
}

// Set stores a cache payload with an EX TTL measured in whole seconds.
func (client *RedisClient) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	seconds, valid := redisTTLSeconds(ttl)
	if !valid {
		return errRedisUnavailable
	}
	reply, err := client.execute(ctx, "SET", key, value, "EX", seconds)
	if err != nil || reply.kind != '+' || reply.text != "OK" {
		return errRedisUnavailable
	}
	return nil
}

// SetNX atomically takes a lock with the required EX TTL.
func (client *RedisClient) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	seconds, valid := redisTTLSeconds(ttl)
	if !valid {
		return false, errRedisUnavailable
	}
	reply, err := client.execute(ctx, "SET", key, value, "NX", "EX", seconds)
	if err != nil {
		return false, errRedisUnavailable
	}
	if reply.nilValue {
		return false, nil
	}
	if reply.kind == '+' && reply.text == "OK" {
		return true, nil
	}
	return false, errRedisUnavailable
}

// CompareAndDelete removes a lock only if this process still owns its opaque
// value. This matches the Python manager's Lua release semantics.
func (client *RedisClient) CompareAndDelete(ctx context.Context, key, value string) error {
	const releaseScript = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end"
	reply, err := client.execute(ctx, "EVAL", releaseScript, "1", key, value)
	if err != nil || reply.kind != ':' {
		return errRedisUnavailable
	}
	return nil
}

// SetIfLockHeld is SET ... EX guarded by lock ownership in one Lua call, with
// an optional publication marker written in the same step.
func (client *RedisClient) SetIfLockHeld(ctx context.Context, lockKey, lockValue, key, value string, ttl time.Duration, publication string) error {
	seconds, valid := redisTTLSeconds(ttl)
	if !valid || strings.ContainsAny(publication, ":@") {
		return errRedisUnavailable
	}
	const script = "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return false end; " +
		"redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3]); " +
		"if ARGV[4] ~= '' then " +
		"local t = redis.call('TIME'); local nowms = t[1] * 1000 + math.floor(t[2] / 1000); " +
		"redis.call('SET', KEYS[3], ARGV[4] .. '@' .. (nowms + ARGV[3] * 1000), 'EX', ARGV[3]) " +
		"else redis.call('DEL', KEYS[3]) end; " +
		"return redis.status_reply('OK')"
	reply, err := client.execute(ctx, "EVAL", script, "3", lockKey, key, publicationKey(key), lockValue, value, seconds, publication)
	if err != nil {
		return errRedisUnavailable
	}
	if reply.nilValue {
		return errLockLost
	}
	if reply.kind != '+' || reply.text != "OK" {
		return errRedisUnavailable
	}
	return nil
}

// ExtendLockIfHeld is EXPIRE guarded by lock ownership in one Lua call.
func (client *RedisClient) ExtendLockIfHeld(ctx context.Context, lockKey, lockValue string, ttl time.Duration) error {
	seconds, valid := redisTTLSeconds(ttl)
	if !valid {
		return errRedisUnavailable
	}
	const script = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('EXPIRE', KEYS[1], ARGV[2]) else return false end"
	reply, err := client.execute(ctx, "EVAL", script, "1", lockKey, lockValue, seconds)
	if err != nil {
		return errRedisUnavailable
	}
	if reply.nilValue || (reply.kind == ':' && reply.text == "0") {
		return errLockLost
	}
	if reply.kind != ':' {
		return errRedisUnavailable
	}
	return nil
}

// WithdrawIfLockHeld is DEL guarded by lock ownership and by the exact record
// the caller means to remove, in one Lua call.
func (client *RedisClient) WithdrawIfLockHeld(ctx context.Context, lockKey, lockValue, key, expected string) error {
	const script = "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return false end; " +
		"if redis.call('GET', KEYS[2]) ~= ARGV[2] then return -1 end; " +
		"redis.call('DEL', KEYS[3]); return redis.call('DEL', KEYS[2])"
	reply, err := client.execute(ctx, "EVAL", script, "3", lockKey, key, publicationKey(key), lockValue, expected)
	if err != nil {
		return errRedisUnavailable
	}
	if reply.nilValue {
		return errLockLost
	}
	if reply.kind != ':' {
		return errRedisUnavailable
	}
	if reply.text == "-1" {
		return errStateChanged
	}
	return nil
}

// GetWithTTL reads a value, its remaining lifetime, its absolute expiry on the
// server clock and the publication marker bound to it, in one atomic call. A
// missing key is present=false; a key without expiry reports a non-positive
// ttl; publication is "" unless a marker describes exactly this record.
func (client *RedisClient) GetWithTTL(ctx context.Context, key string) (string, time.Duration, int64, string, bool, error) {
	const script = "local v = redis.call('GET', KEYS[1]); if not v then return false end; " +
		"local t = redis.call('TIME'); local nowms = t[1] * 1000 + math.floor(t[2] / 1000); " +
		"local ttl = redis.call('PTTL', KEYS[1]); " +
		"local m = redis.call('GET', KEYS[2]); if not m then m = '' end; " +
		"return (nowms + ttl) .. ':' .. ttl .. ':' .. m .. ':' .. v"
	reply, err := client.execute(ctx, "EVAL", script, "2", key, publicationKey(key))
	if err != nil {
		return "", 0, 0, "", false, errRedisUnavailable
	}
	if reply.nilValue {
		return "", 0, 0, "", false, nil
	}
	if reply.kind != '$' {
		return "", 0, 0, "", false, errRedisUnavailable
	}
	parts := strings.SplitN(reply.text, ":", 4)
	if len(parts) != 4 {
		return "", 0, 0, "", false, errRedisUnavailable
	}
	absolute, absErr := strconv.ParseInt(parts[0], 10, 64)
	ms, ttlErr := strconv.ParseInt(parts[1], 10, 64)
	if absErr != nil || ttlErr != nil || ms > int64((1<<63-1)/int64(time.Millisecond)) {
		return "", 0, 0, "", false, errRedisUnavailable
	}
	return parts[3], time.Duration(ms) * time.Millisecond, absolute, boundPublication(parts[2], absolute), true, nil
}

// boundPublication returns the attempt id of a "<attempt>@<expiry-ms>" marker
// if, and only if, its recorded expiry matches the record's current expiry. A
// later write by anyone else moves the expiry, so it cannot inherit the marker.
func boundPublication(marker string, serverExpiryMs int64) string {
	attempt, expiry, found := strings.Cut(marker, "@")
	if !found || attempt == "" {
		return ""
	}
	recorded, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		return ""
	}
	delta := recorded - serverExpiryMs
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Millisecond > markerTolerance {
		return ""
	}
	return attempt
}

// Held reports whether key exists; the approval lock-wait loop uses it to
// detect that the lock holder finished, regardless of the value it stored.
func (client *RedisClient) Held(ctx context.Context, key string) (bool, error) {
	reply, err := client.execute(ctx, "EXISTS", key)
	if err != nil || reply.kind != ':' {
		return false, errRedisUnavailable
	}
	return reply.text == "1", nil
}

func redisTTLSeconds(ttl time.Duration) (string, bool) {
	if ttl <= 0 || ttl%time.Second != 0 {
		return "", false
	}
	seconds := int64(ttl / time.Second)
	if seconds <= 0 {
		return "", false
	}
	return strconv.FormatInt(seconds, 10), true
}

func (client *RedisClient) execute(ctx context.Context, values ...string) (redisReply, error) {
	connection, err := client.dial(ctx)
	if err != nil {
		return redisReply{}, errRedisUnavailable
	}
	defer connection.Close()
	if err := setRedisDeadline(connection, ctx); err != nil {
		return redisReply{}, errRedisUnavailable
	}
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	if client.password != "" {
		arguments := []string{"AUTH"}
		if client.username != "" {
			arguments = append(arguments, client.username)
		}
		arguments = append(arguments, client.password)
		if err := writeRESPArray(writer, arguments...); err != nil {
			return redisReply{}, errRedisUnavailable
		}
		reply, err := readRESPReply(reader)
		if err != nil || reply.kind != '+' || reply.text != "OK" {
			return redisReply{}, errRedisUnavailable
		}
	}
	if client.database != 0 {
		if err := writeRESPArray(writer, "SELECT", strconv.Itoa(client.database)); err != nil {
			return redisReply{}, errRedisUnavailable
		}
		reply, err := readRESPReply(reader)
		if err != nil || reply.kind != '+' || reply.text != "OK" {
			return redisReply{}, errRedisUnavailable
		}
	}
	if err := writeRESPArray(writer, values...); err != nil {
		return redisReply{}, errRedisUnavailable
	}
	reply, err := readRESPReply(reader)
	if err != nil {
		return redisReply{}, errRedisUnavailable
	}
	return reply, nil
}

func (client *RedisClient) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: redisDialTimeout}
	connection, err := dialer.DialContext(ctx, "tcp", client.address)
	if err != nil || client.scheme != "rediss" {
		return connection, err
	}
	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: client.server,
	})
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return tlsConnection, nil
}

func setRedisDeadline(connection net.Conn, ctx context.Context) error {
	deadline := time.Now().Add(redisDialTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return connection.SetDeadline(deadline)
}

func writeRESPArray(writer *bufio.Writer, values ...string) error {
	if len(values) == 0 || len(values) > 12 {
		return errors.New("invalid redis command")
	}
	if _, err := fmt.Fprintf(writer, "*%d\r\n", len(values)); err != nil {
		return err
	}
	for _, value := range values {
		if len(value) > redisReplyLimit {
			return errors.New("redis command too large")
		}
		if _, err := fmt.Fprintf(writer, "$%d\r\n%s\r\n", len(value), value); err != nil {
			return err
		}
	}
	return writer.Flush()
}

type redisReply struct {
	kind     byte
	text     string
	nilValue bool
}

func readRESPReply(reader *bufio.Reader) (redisReply, error) {
	marker, err := reader.ReadByte()
	if err != nil {
		return redisReply{}, err
	}
	switch marker {
	case '+':
		line, err := readRESPLine(reader)
		return redisReply{kind: marker, text: line}, err
	case '-':
		_, err := readRESPLine(reader)
		if err != nil {
			return redisReply{}, err
		}
		return redisReply{}, errors.New("redis error reply")
	case ':':
		line, err := readRESPLine(reader)
		if err != nil {
			return redisReply{}, err
		}
		if _, err := strconv.ParseInt(line, 10, 64); err != nil {
			return redisReply{}, err
		}
		return redisReply{kind: marker, text: line}, nil
	case '$':
		lengthLine, err := readRESPLine(reader)
		if err != nil {
			return redisReply{}, err
		}
		length, err := strconv.Atoi(lengthLine)
		if err != nil {
			return redisReply{}, err
		}
		if length == -1 {
			return redisReply{kind: marker, nilValue: true}, nil
		}
		if length < 0 || length > redisReplyLimit {
			return redisReply{}, errors.New("invalid redis bulk length")
		}
		payload := make([]byte, length+2)
		if _, err := io.ReadFull(reader, payload); err != nil || payload[length] != '\r' || payload[length+1] != '\n' {
			return redisReply{}, errors.New("invalid redis bulk payload")
		}
		return redisReply{kind: marker, text: string(payload[:length])}, nil
	case '_':
		line, err := readRESPLine(reader)
		if err != nil || line != "" {
			return redisReply{}, errors.New("invalid redis null")
		}
		return redisReply{kind: marker, nilValue: true}, nil
	default:
		return redisReply{}, errors.New("unexpected redis reply")
	}
}

func readRESPLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil || len(line) < 2 || len(line) > redisReplyLimit || !strings.HasSuffix(line, "\r\n") {
		return "", errors.New("invalid redis line")
	}
	return strings.TrimSuffix(line, "\r\n"), nil
}

// TTL returns the remaining lifetime; Redis reports missing or persistent keys
// as negative values, neither of which is a fresh approval record.
func (client *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	reply, err := client.execute(ctx, "PTTL", key)
	if err != nil || reply.kind != ':' {
		return 0, errRedisUnavailable
	}
	ms, err := strconv.ParseInt(reply.text, 10, 64)
	if err != nil || ms > int64((1<<63-1)/int64(time.Millisecond)) {
		return 0, errRedisUnavailable
	}
	return time.Duration(ms) * time.Millisecond, nil
}
