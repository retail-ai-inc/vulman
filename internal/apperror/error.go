// Package apperror separates public, translatable messages from diagnostic causes.
package apperror

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Message is safe to persist and send to the desktop. Causes contain only other
// public messages; underlying errors and external command output stay in Go.
type Message struct {
	Code     string            `json:"code"`
	Params   map[string]string `json:"params,omitempty"`
	Causes   []Message         `json:"causes,omitempty"`
	Fallback string            `json:"fallback,omitempty"`
}

type Error struct {
	message Message
	err     error
}

func New(code, text string) *Error {
	return &Error{message: Message{Code: code, Fallback: text}, err: errors.New(text)}
}

// Newf keeps normal Go wrapping semantics while exposing named positional
// parameters for translation. Error arguments become structured causes.
func Newf(code, format string, args ...any) *Error {
	message := Message{Code: code, Params: make(map[string]string)}
	publicArgs := make([]any, len(args))
	for i, arg := range args {
		if err, ok := arg.(error); ok {
			message.Causes = append(message.Causes, *Public(err))
			publicArgs[i] = ""
		} else {
			message.Params[fmt.Sprintf("arg%d", i)] = fmt.Sprint(arg)
			publicArgs[i] = arg
		}
	}

	message.Fallback = strings.TrimRight(strings.TrimSpace(fmt.Sprintf(strings.ReplaceAll(format, "%w", "%v"), publicArgs...)), ":; ·")
	return &Error{message: message, err: fmt.Errorf(format, args...)}
}

func (e *Error) Error() string { return e.message.English() }

func (e *Error) Unwrap() error { return e.err }

func (e *Error) PublicMessage() Message { return e.message }

// English is a safe fallback for older consumers and the command-line report.
func (m Message) English() string {
	text := m.Fallback
	for _, cause := range m.Causes {
		if text != "" {
			text += ": "
		}
		text += cause.English()
	}
	return text
}

// Expose protects the Wails outer error string as well as its structured cause.
// The original cause remains available to Go via errors.Is and errors.As.
func Expose(err error) error {
	if err == nil {
		return nil
	}
	return &Error{message: *Public(err), err: err}
}

// Public never copies an unknown error's text. Such errors may contain tokens,
// credential-bearing URLs, or external output. Classification retains useful
// troubleshooting guidance without exposing those details.
func Public(err error) *Message {
	return public(err, 0)
}

func public(err error, depth int) *Message {
	if err == nil {
		return nil
	}
	if depth < 12 {
		if value, ok := err.(interface{ PublicMessage() Message }); ok {
			message := value.PublicMessage()
			return &message
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			message := &Message{Code: "multiple"}
			for _, child := range joined.Unwrap() {
				if item := public(child, depth+1); item != nil {
					message.Causes = append(message.Causes, *item)
				}
				if len(message.Causes) == 8 {
					break
				}
			}
			return message
		}
		if cause := errors.Unwrap(err); cause != nil {
			return public(cause, depth+1)
		}
	}

	code, text := "unexpected", "An unexpected error occurred. Please try again."
	switch {
	case errors.Is(err, context.Canceled):
		code, text = "cancelled", "The operation was cancelled."
	case errors.Is(err, context.DeadlineExceeded):
		code, text = "timeout", "The operation timed out. Please try again."
	case errors.Is(err, os.ErrPermission):
		code, text = "permission_denied", "Permission denied. Check file or tool permissions."
	case errors.Is(err, os.ErrNotExist):
		code, text = "file_missing", "A required file or folder was not found."
	case errors.Is(err, exec.ErrNotFound):
		code, text = "tool_missing", "A required tool was not found. Check its installation and PATH."
	case errors.Is(err, exec.ErrDot):
		code, text = "tool_relative_path", "The tool must be installed on an absolute PATH entry."
	default:
		var network net.Error
		if errors.As(err, &network) {
			code, text = "network", "The network request failed. Check your connection and try again."
			if network.Timeout() {
				code, text = "timeout", "The operation timed out. Please try again."
			}
		}
	}
	return &Message{Code: code, Fallback: text}
}
