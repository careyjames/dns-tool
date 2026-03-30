// dns-tool:scrutiny plumbing
package logging

import (
        "io"
        "log/slog"
        "os"
        "time"

        "github.com/jackc/pgx/v5/pgxpool"
)

type Logger struct {
        FileWriter *RotatingFileWriter
        DBSink     *DBSink
        Discord    *DiscordSink
        done       chan struct{}
}

func Setup(pool *pgxpool.Pool, discordWebhookURL string) (*Logger, error) {
        logDir := "logs"
        if dir := os.Getenv("LOG_DIR"); dir != "" {
                logDir = dir
        }

        fileWriter, err := NewRotatingFileWriter(logDir, "dnstool")
        if err != nil {
                return nil, err
        }

        var dbSink *DBSink
        if pool != nil {
                dbSink = NewDBSink(pool)
        }

        var discordSink *DiscordSink
        if discordWebhookURL != "" {
                discordSink = NewDiscordSink(discordWebhookURL)
        }

        combined := io.MultiWriter(os.Stdout, fileWriter)

        handler := NewMultiHandler(Config{
                FileWriter:  combined,
                DBSink:      dbSink,
                DiscordSink: discordSink,
                MinLevel:    slog.LevelDebug,
        })

        slog.SetDefault(slog.New(handler))

        logger := &Logger{
                FileWriter: fileWriter,
                DBSink:     dbSink,
                Discord:    discordSink,
                done:       make(chan struct{}),
        }
        go logger.fileCleanupLoop()

        return logger, nil
}

func (l *Logger) Close() {
        close(l.done)
        if l.FileWriter != nil {
                l.FileWriter.Close()
        }
        if l.DBSink != nil {
                l.DBSink.Close()
        }
}

func (l *Logger) fileCleanupLoop() {
        ticker := time.NewTicker(1 * time.Hour)
        defer ticker.Stop()
        for {
                select {
                case <-ticker.C:
                        if l.FileWriter != nil {
                                l.FileWriter.Cleanup()
                        }
                case <-l.done:
                        return
                }
        }
}
