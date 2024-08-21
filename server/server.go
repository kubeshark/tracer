package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/kubeshark/tracer/server/middlewares"
	"github.com/rs/zerolog/log"
)

const (
	ProfilingEnabledEnvVarName = "PROFILING_ENABLED"
)

func Build() *gin.Engine {
	ginApp := gin.New()
	ginApp.Use(middlewares.DefaultStructuredLogger())
	ginApp.Use(gin.Recovery())

	ginApp.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "It's running.")
	})

	ginApp.Use(middlewares.CORSMiddleware())

	pprof.Register(ginApp)

	return ginApp
}

func GetProfilingEnabled() bool {
	val := os.Getenv(ProfilingEnabledEnvVarName)
	return val != "" && val != "false"
}

func Start(app *gin.Engine, port int) {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals,
		os.Interrupt,    // this catch ctrl + c
		syscall.SIGTSTP, // this catch ctrl + z
	)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: app,
	}

	go func() {
		// Run server.
		log.Info().Int("port", port).Msg("Starting the server...")
		if err := app.Run(fmt.Sprintf(":%d", port)); err != nil {
			log.Error().Err(err).Msg("Server is not running!")
		}
	}()

	<-signals
	log.Warn().Msg("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	if err != nil {
		log.Error().Err(err).Send()
	}
}
