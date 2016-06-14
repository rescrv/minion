package minion

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"regexp"
)

type token struct {
	typ  int
	line int
	val  string
}

var reserved = map[string]int{
	"source":       SOURCE,
	"fetch":        FETCH,
	"sha256":       SHA256,
	"git":          GIT,
	"branch":       BRANCH,
	"process":      PROCESS,
	"dockerfile":   DOCKERFILE,
	"dependencies": DEPENDENCIES,
	"artifacts":    ARTIFACTS,
	"soft":         SOFT,
	"full":         FULL,
}

var eof = rune(0)

type Lexer struct {
	r      *bufio.Reader
	lineno int
}

func NewLexer(r io.Reader) *Lexer {
	return &Lexer{r: bufio.NewReader(r), lineno: 1}
}

func (l *Lexer) read() rune {
	ch, _, err := l.r.ReadRune()
	if err != nil {
		return eof
	}
	return ch
}

func (l *Lexer) unread() {
	_ = l.r.UnreadRune()
}

const sha_regexp string = "[0-9a-f]{64}"
const url_regexp string = "(http|https|ftp|ssh|git)://[^\n \t;#]+"

func (l *Lexer) Next() (tok token) {
	for {
		ch := l.read()

		if ch == eof {
			break
		} else if isWhitespace(ch) {
			l.skipWhitespace()
		} else if ch == '#' {
			l.skipRestOfLine()
		} else if ch == ';' {
			return token{SEMICOLON, l.lineno, ";"}
		} else if ch == ',' {
			return token{COMMA, l.lineno, ","}
		} else if ch == '=' {
			ch = l.read()
			if ch != '>' {
				panic(errors.New("expected =>"))
			}
			return token{ARROW, l.lineno, "=>"}
		} else {
			l.unread()
			str := l.readUntilNextToken()
			if match, err := regexp.MatchString(sha_regexp, str); match && err == nil {
				return token{SHA256SUM, l.lineno, str}
			}
			if match, err := regexp.MatchString(url_regexp, str); match && err == nil {
				return token{URL, l.lineno, str}
			}
			if res, ok := reserved[str]; ok {
				return token{res, l.lineno, str}
			}
			return token{IDENTIFIER, l.lineno, str}
		}
	}

	return token{0, l.lineno, ""}
}

func (l *Lexer) skipWhitespace() {
	for {
		ch := l.read()
		if ch == eof {
			break
		}
		if isNewline(ch) {
			l.lineno++
		}
		if !isWhitespace(ch) {
			l.unread()
			break
		}
	}
}

func (l *Lexer) skipRestOfLine() {
	for {
		ch := l.read()
		if ch == eof || isNewline(ch) {
			l.lineno++
			break
		}
	}
}

func (l *Lexer) readUntilNextToken() string {
	var buf bytes.Buffer
	for {
		ch := l.read()
		if ch == eof {
			break
		} else if isTokenBreakPoint(ch) {
			l.unread()
			break
		} else {
			buf.WriteRune(ch)
		}
	}
	return buf.String()
}

func isWhitespace(ch rune) bool {
	return ch == ' ' || ch == '\t' || isNewline(ch)
}

func isNewline(ch rune) bool {
	return ch == '\n' || ch == '\r'
}

func isTokenBreakPoint(ch rune) bool {
	return ch == '#' || ch == ';' || ch == ',' || ch == '=' || isWhitespace(ch)
}
