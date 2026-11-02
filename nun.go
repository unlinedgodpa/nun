package jitoclient

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-tron/base58"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/wangzhihao-dev/jitoclient/pb/auth"
	"github.com/wangzhihao-dev/jitoclient/pb/bundle"
	"github.com/wangzhihao-dev/jitoclient/pb/packet"
	"github.com/wangzhihao-dev/jitoclient/pb/searcher"
)

type Option func(*Client)

func WithTLS(cfg *tls.Config) Option {
	return func(c *Client) { c.tlsCfg = cfg }
}

func WithRefreshMargin(d time.Duration) Option {
	return func(c *Client) { c.margin = d }
}

func WithLogger(l *log.Logger) Option {
	return func(c *Client) { c.logger = l }
}

type Stats struct {
	Sent, Landed, Failed uint64
}

func (s Stats) Rate() float64 {
	if s.Sent == 0 {
		return 0
	}
	return float64(s.Landed) / float64(s.Sent)
}

type Client struct {
	conn     *grpc.ClientConn
	authSvc  auth.AuthServiceClient
	searchSv searcher.SearcherServiceClient
	priv     ed25519.PrivateKey
	pubB58   string
	tlsCfg   *tls.Config
	margin   time.Duration
	logger   *log.Logger

	mu         sync.RWMutex
	accessTok  string
	refreshTok string
	accessExp  time.Time
	refreshEx  time.Time

	sent   atomic.Uint64
	landed atomic.Uint64
	failed atomic.Uint64

	seenMu sync.Mutex
	seen   map[string]struct{}

	cancel context.CancelFunc
}

func Dial(ctx context.Context, endpoint string, key ed25519.PrivateKey, opts ...Option) (*Client, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("jitoclient: invalid private key")
	}
	c := &Client{
		priv:   key,
		pubB58: base58.Encode(key.Public().(ed25519.PublicKey)),
		margin: 2 * time.Minute,
		logger: log.Default(),
		seen:   map[string]struct{}{},
	}
	for _, o := range opts {
		o(c)
	}
	if c.tlsCfg == nil {
		c.tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(c.tlsCfg)),
		grpc.WithPerRPCCredentials(c))
	if err != nil {
		return nil, fmt.Errorf("jitoclient: dial: %w", err)
	}
	c.conn = conn
	c.authSvc = auth.NewAuthServiceClient(conn)
	c.searchSv = searcher.NewSearcherServiceClient(conn)
	if err := c.login(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	bg, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go c.refreshLoop(bg)
	return c, nil
}

func (c *Client) Close() error {
	c.cancel()
	return c.conn.Close()
}

func (c *Client) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]string{"authorization": "Bearer " + c.accessTok}, nil
}

func (c *Client) RequireTransportSecurity() bool { return true }

func (c *Client) login(ctx context.Context) error {
	pub := c.priv.Public().(ed25519.PublicKey)
	ch, err := c.authSvc.GenerateAuthChallenge(ctx, &auth.GenerateAuthChallengeRequest{
		Role:   auth.Role_SEARCHER,
		Pubkey: pub,
	})
	if err != nil {
		return fmt.Errorf("jitoclient: challenge: %w", err)
	}
	payload := c.pubB58 + "-" + ch.GetChallenge()
	sig := ed25519.Sign(c.priv, []byte(payload))
	resp, err := c.authSvc.GenerateAuthTokens(ctx, &auth.GenerateAuthTokensRequest{
		Challenge:       payload,
		ClientPubkey:    pub,
		SignedChallenge: sig,
	})
	if err != nil {
		return fmt.Errorf("jitoclient: tokens: %w", err)
	}
	c.store(resp.GetAccessToken(), resp.GetRefreshToken())
	return nil
}

func (c *Client) store(access, refresh *auth.Token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if access != nil {
		c.accessTok = access.GetValue()
		c.accessExp = access.GetExpiresAtUtc().AsTime()
	}
	if refresh != nil {
		c.refreshTok = refresh.GetValue()
		c.refreshEx = refresh.GetExpiresAtUtc().AsTime()
	}
}

func (c *Client) refreshLoop(ctx context.Context) {
	for {
		c.mu.RLock()
		wait := time.Until(c.accessExp) - c.margin
		c.mu.RUnlock()
		wait = max(wait, time.Second)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := c.refresh(ctx); err != nil {
			c.logger.Printf("jitoclient: refresh failed: %v", err)
			if err := c.login(ctx); err != nil {
				c.logger.Printf("jitoclient: relogin failed: %v", err)
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func (c *Client) refresh(ctx context.Context) error {
	c.mu.RLock()
	rt, rtExp := c.refreshTok, c.refreshEx
	c.mu.RUnlock()
	if time.Now().After(rtExp) {
		return errors.New("jitoclient: refresh token expired")
	}
	resp, err := c.authSvc.RefreshAccessToken(ctx, &auth.RefreshAccessTokenRequest{RefreshToken: rt})
	if err != nil {
		return err
	}
	c.store(resp.GetAccessToken(), nil)
	return nil
}

func (c *Client) SendBundle(ctx context.Context, txs [][]byte) (string, error) {
	pkts := make([]*packet.Packet, 0, len(txs))
	for _, tx := range txs {
		pkts = append(pkts, &packet.Packet{Data: tx, Meta: &packet.Meta{Size: uint64(len(tx))}})
	}
	resp, err := c.searchSv.SendBundle(ctx, &searcher.SendBundleRequest{
		Bundle: &bundle.Bundle{Packets: pkts},
	})
	if err != nil {
		return "", fmt.Errorf("jitoclient: send: %w", err)
	}
	c.sent.Add(1)
	return resp.GetUuid(), nil
}

func (c *Client) WatchResults(ctx context.Context) error {
	stream, err := c.searchSv.SubscribeBundleResults(ctx, &searcher.SubscribeBundleResultsRequest{})
	if err != nil {
		return fmt.Errorf("jitoclient: subscribe: %w", err)
	}
	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) || ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return fmt.Errorf("jitoclient: stream: %w", err)
		}
		switch {
		case res.GetProcessed() != nil, res.GetFinalized() != nil:
			if c.firstLanding(res.GetBundleId()) {
				c.landed.Add(1)
			}
		case res.GetRejected() != nil, res.GetDropped() != nil:
			c.failed.Add(1)
		}
	}
}

func (c *Client) firstLanding(id string) bool {
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	if _, ok := c.seen[id]; ok {
		return false
	}
	c.seen[id] = struct{}{}
	return true
}

func (c *Client) Stats() Stats {
	return Stats{Sent: c.sent.Load(), Landed: c.landed.Load(), Failed: c.failed.Load()}
}
