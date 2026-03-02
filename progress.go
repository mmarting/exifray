package main

import (
	"os"

	"github.com/schollz/progressbar/v3"
)

// ProgressBar abstracts progress tracking so it can be disabled in quiet/JSON mode.
type ProgressBar interface {
	Add(n int)
	Finish()
}

// newProgressBar creates a visible progress bar for terminal output.
func newProgressBar(total int, description string) ProgressBar {
	bar := progressbar.NewOptions(total,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetWidth(40),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
	return &realBar{bar: bar}
}

// newNoopBar returns a no-op progress bar for quiet/JSON mode.
func newNoopBar() ProgressBar {
	return &noopBar{}
}

type realBar struct {
	bar *progressbar.ProgressBar
}

func (b *realBar) Add(n int) { b.bar.Add(n) }
func (b *realBar) Finish()   { b.bar.Finish() }

type noopBar struct{}

func (b *noopBar) Add(n int) {}
func (b *noopBar) Finish()   {}
