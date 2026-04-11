package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

// Live returns database liveness status.
// Response is plain text: "UP" when DB ping succeeds, otherwise "DOWN".
func (h *Handler) Live(c echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
	defer cancel()

	if err := h.db.PingContext(ctx); err != nil {
		return c.String(http.StatusServiceUnavailable, "DOWN")
	}

	return c.String(http.StatusOK, "UP")
}
