package main

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

type AppConfig struct {
	Port         string
	DatabaseURL  string
	AdminToken   string
	CorsOrigin   string
	BaseURL      string
	EmailFrom    string
	VapidPublic  string
	VapidPrivate string
}

type TrackRequest struct {
	OfferID     string `json:"offerId" binding:"required"`
	PagePath    string `json:"pagePath"`
	Referrer    string `json:"referrer"`
	UtmSource   string `json:"utmSource"`
	UtmMedium   string `json:"utmMedium"`
	UtmCampaign string `json:"utmCampaign"`
	UtmTerm     string `json:"utmTerm"`
	UtmContent  string `json:"utmContent"`
}

type SubscribeRequest struct {
	Email    string `json:"email"`
	WhatsApp string `json:"whatsapp"`
	Consent  bool   `json:"consent"`
}

type PushSubscription struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

type PushMessage struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"url"`
}

func main() {
	_ = godotenv.Load()
	cfg := loadConfig()

	pool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		panic(err)
	}
	defer pool.Close()

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{cfg.CorsOrigin},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	r.POST("/track", func(c *gin.Context) {
		var req TrackRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
			return
		}
		var exists bool
		err := pool.QueryRow(c, "SELECT EXISTS(SELECT 1 FROM offers WHERE id=$1 AND is_active=true)", req.OfferID).Scan(&exists)
		if err != nil || !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "offer not found"})
			return
		}
		clickID := generateID()
		_, err = pool.Exec(
			c,
			`INSERT INTO clicks (id, offer_id, page_path, referrer, utm_source, utm_medium, utm_campaign, utm_term, utm_content, ip, user_agent, device, created_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			clickID,
			req.OfferID,
			req.PagePath,
			req.Referrer,
			req.UtmSource,
			req.UtmMedium,
			req.UtmCampaign,
			req.UtmTerm,
			req.UtmContent,
			c.ClientIP(),
			c.Request.UserAgent(),
			detectDevice(c.Request.UserAgent()),
			time.Now().UTC(),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		redirectURL := strings.TrimRight(cfg.BaseURL, "/") + "/r/" + req.OfferID + "?cid=" + clickID
		c.JSON(http.StatusCreated, gin.H{"redirectUrl": redirectURL})
	})

	r.GET("/go/:offerId", func(c *gin.Context) {
		offerID := c.Param("offerId")
		var affiliateURL string
		err := pool.QueryRow(c,
			"SELECT affiliate_url FROM offers WHERE id=$1 AND is_active=true",
			offerID,
		).Scan(&affiliateURL)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "offer not found"})
			return
		}

		clickID := generateID()
		src := c.Query("src")
		page := c.Query("page")
		utmSource := c.Query("utm_source")
		utmMedium := c.Query("utm_medium")
		utmCampaign := c.Query("utm_campaign")
		utmTerm := c.Query("utm_term")
		utmContent := c.Query("utm_content")
		if utmSource == "" {
			utmSource = src
		}
		_, _ = pool.Exec(
			c,
			`INSERT INTO clicks (id, offer_id, page_path, referrer, utm_source, utm_medium, utm_campaign, utm_term, utm_content, ip, user_agent, device, created_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			clickID,
			offerID,
			page,
			c.Request.Referer(),
			utmSource,
			utmMedium,
			utmCampaign,
			utmTerm,
			utmContent,
			c.ClientIP(),
			c.Request.UserAgent(),
			detectDevice(c.Request.UserAgent()),
			time.Now().UTC(),
		)

		c.Redirect(http.StatusFound, affiliateURL)
	})

	r.GET("/r/:offerId", func(c *gin.Context) {
		offerID := c.Param("offerId")
		var affiliateURL string
		err := pool.QueryRow(c,
			"SELECT affiliate_url FROM offers WHERE id=$1 AND is_active=true",
			offerID,
		).Scan(&affiliateURL)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "offer not found"})
			return
		}

		clickID := c.Query("cid")
		if clickID != "" {
			_, _ = pool.Exec(c,
				"UPDATE clicks SET redirected_at=$1 WHERE id=$2",
				time.Now().UTC(), clickID,
			)
		}

		c.Redirect(http.StatusFound, affiliateURL)
	})

	r.POST("/subscribe", func(c *gin.Context) {
		var req SubscribeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
			return
		}
		if !req.Consent || (req.Email == "" && req.WhatsApp == "") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "consent and contact required"})
			return
		}
		_, err := pool.Exec(
			c,
			`INSERT INTO subscribers (email, whatsapp, consent, created_at) VALUES ($1,$2,$3,$4)`,
			req.Email,
			req.WhatsApp,
			req.Consent,
			time.Now().UTC(),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		// TODO: trigger welcome email using SES or email provider.
		c.JSON(http.StatusCreated, gin.H{"status": "subscribed", "from": cfg.EmailFrom})
	})

	r.POST("/push/subscribe", func(c *gin.Context) {
		var sub PushSubscription
		if err := c.ShouldBindJSON(&sub); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
			return
		}
		_, err := pool.Exec(c,
			`INSERT INTO push_subscriptions (endpoint, p256dh, auth, user_agent, created_at)
			 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (endpoint) DO NOTHING`,
			sub.Endpoint, sub.Keys.P256dh, sub.Keys.Auth, c.Request.UserAgent(), time.Now().UTC(),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"status": "subscribed"})
	})

	admin := r.Group("/admin")
	admin.Use(adminAuth(cfg))

	admin.GET("/offers", func(c *gin.Context) {
		rows, err := pool.Query(c, `SELECT id, name, affiliate_url, category, payout_type, is_active FROM offers ORDER BY name`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		defer rows.Close()
		offers := []gin.H{}
		for rows.Next() {
			var id, name, url, category, payout string
			var active bool
			_ = rows.Scan(&id, &name, &url, &category, &payout, &active)
			offers = append(offers, gin.H{
				"id":           id,
				"name":         name,
				"affiliateUrl": url,
				"category":     category,
				"payoutType":   payout,
				"isActive":     active,
			})
		}
		c.JSON(http.StatusOK, gin.H{"offers": offers})
	})

	admin.PUT("/offers/:id", func(c *gin.Context) {
		id := c.Param("id")
		var payload struct {
			Name         string `json:"name"`
			AffiliateURL string `json:"affiliateUrl"`
			Category     string `json:"category"`
			PayoutType   string `json:"payoutType"`
			IsActive     bool   `json:"isActive"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
			return
		}
		_, err := pool.Exec(c,
			`UPDATE offers SET name=$1, affiliate_url=$2, category=$3, payout_type=$4, is_active=$5 WHERE id=$6`,
			payload.Name, payload.AffiliateURL, payload.Category, payload.PayoutType, payload.IsActive, id,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "updated"})
	})

	admin.GET("/stats", func(c *gin.Context) {
		byOffer := []gin.H{}
		rows, err := pool.Query(c,
			`SELECT o.id, o.name, o.payout_type, COUNT(c.id) FROM offers o
			 LEFT JOIN clicks c ON c.offer_id = o.id
			 GROUP BY o.id, o.name, o.payout_type ORDER BY COUNT(c.id) DESC`,
		)
		if err == nil {
			for rows.Next() {
				var id, name, payout string
				var count int
				_ = rows.Scan(&id, &name, &payout, &count)
				byOffer = append(byOffer, gin.H{
					"id":         id,
					"name":       name,
					"payoutType": payout,
					"clicks":     count,
				})
			}
			rows.Close()
		}

		bySource := map[string]int{}
		rows, err = pool.Query(c,
			`SELECT COALESCE(NULLIF(utm_source, ''), 'direct') AS source, COUNT(id)
			 FROM clicks GROUP BY source ORDER BY COUNT(id) DESC`,
		)
		if err == nil {
			for rows.Next() {
				var source string
				var count int
				_ = rows.Scan(&source, &count)
				bySource[source] = count
			}
			rows.Close()
		}

		var totalClicks int
		_ = pool.QueryRow(c, `SELECT COUNT(*) FROM clicks`).Scan(&totalClicks)

		c.JSON(http.StatusOK, gin.H{
			"byOffer":     byOffer,
			"bySource":    bySource,
			"totalClicks": totalClicks,
		})
	})

	admin.GET("/clicks", func(c *gin.Context) {
		rows, err := pool.Query(c,
			`SELECT id, offer_id, page_path, utm_source, utm_medium, utm_campaign, created_at FROM clicks ORDER BY created_at DESC LIMIT 200`,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		defer rows.Close()
		results := []gin.H{}
		for rows.Next() {
			var id, offerID, pagePath, utmSource, utmMedium, utmCampaign string
			var created time.Time
			_ = rows.Scan(&id, &offerID, &pagePath, &utmSource, &utmMedium, &utmCampaign, &created)
			results = append(results, gin.H{
				"id":          id,
				"offerId":     offerID,
				"pagePath":    pagePath,
				"utmSource":   utmSource,
				"utmMedium":   utmMedium,
				"utmCampaign": utmCampaign,
				"createdAt":   created,
			})
		}
		c.JSON(http.StatusOK, gin.H{"clicks": results})
	})

	admin.POST("/push", func(c *gin.Context) {
		var msg PushMessage
		if err := c.ShouldBindJSON(&msg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
			return
		}
		if cfg.VapidPublic == "" || cfg.VapidPrivate == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "vapid keys missing"})
			return
		}

		rows, err := pool.Query(c, `SELECT endpoint, p256dh, auth FROM push_subscriptions`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
			return
		}
		defer rows.Close()
		sent := 0
		for rows.Next() {
			var endpoint, p256dh, auth string
			_ = rows.Scan(&endpoint, &p256dh, &auth)
			sub := &webpush.Subscription{
				Endpoint: endpoint,
				Keys: webpush.Keys{
					P256dh: p256dh,
					Auth:   auth,
				},
			}
			payload := []byte(`{"title":"` + msg.Title + `","body":"` + msg.Body + `","url":"` + msg.URL + `"}`)
			_, err := webpush.SendNotification(payload, sub, &webpush.Options{
				VAPIDPublicKey:  cfg.VapidPublic,
				VAPIDPrivateKey: cfg.VapidPrivate,
				Subscriber:      cfg.EmailFrom,
				TTL:             60,
			})
			if err == nil {
				sent++
			}
		}
		c.JSON(http.StatusOK, gin.H{"sent": sent})
	})

	_ = r.Run(":" + cfg.Port)
}

func loadConfig() AppConfig {
	return AppConfig{
		Port:         envOr("PORT", "8080"),
		DatabaseURL:  envOr("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/loanaffiliate?sslmode=disable"),
		AdminToken:   envOr("ADMIN_TOKEN", "changeme"),
		CorsOrigin:   envOr("CORS_ORIGIN", "http://localhost:5173"),
		BaseURL:      envOr("BASE_URL", "http://localhost:8080"),
		EmailFrom:    envOr("EMAIL_FROM", "alerts@your-domain.com"),
		VapidPublic:  envOr("VAPID_PUBLIC_KEY", ""),
		VapidPrivate: envOr("VAPID_PRIVATE_KEY", ""),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func generateID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func detectDevice(ua string) string {
	low := strings.ToLower(ua)
	if strings.Contains(low, "mobile") || strings.Contains(low, "android") || strings.Contains(low, "iphone") {
		return "mobile"
	}
	if strings.Contains(low, "ipad") || strings.Contains(low, "tablet") {
		return "tablet"
	}
	return "desktop"
}

func adminAuth(cfg AppConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if token != cfg.AdminToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}
}
