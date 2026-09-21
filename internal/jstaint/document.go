package jstaint

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
	"github.com/tdewolff/parse/v2/html"
)

// isNonJSDocument is only used after JavaScript parsing fails. The deep walk
// supplies every file regardless of extension, so token matches in data and
// templates must not be reported as JavaScript coverage failures. Ambiguous
// content stays a parse failure; filenames never decide which files to skip.
func isNonJSDocument(src []byte) bool {
	src = bytes.TrimSpace(bytes.TrimPrefix(src, []byte("\xef\xbb\xbf")))
	if opensWithPHPTag(src) || json.Valid(src) {
		return true
	}

	lexer := html.NewLexer(parse.NewInputBytes(src[:len(src):len(src)]))
	for {
		token, data := lexer.Next()
		switch token {
		case html.CommentToken:
			// HTML comments can precede the document's first tag.
			continue
		case html.TextToken:
			if len(bytes.TrimSpace(data)) == 0 {
				continue
			}
		case html.StartTagToken, html.DoctypeToken:
			return true
		}
		break
	}
	return isStylesheet(src) || isTranslationCatalog(src)
}

func opensWithPHPTag(src []byte) bool {
	if bytes.HasPrefix(src, []byte("<?=")) {
		return true
	}
	const tag = "<?php"
	if len(src) < len(tag) || !bytes.EqualFold(src[:len(tag)], []byte(tag)) {
		return false
	}
	// The long opening tag requires whitespace, unlike the echo tag.
	return len(src) == len(tag) || bytes.ContainsAny(src[len(tag):len(tag)+1], " \t\r\n")
}

func isStylesheet(src []byte) bool {
	// CSS parsers recover at EOF, even from unclosed strings and blocks. Only
	// classify a complete token stream so malformed JS retains its warning.
	if !completeCSSTokens(src) {
		return false
	}
	p := css.NewParser(parse.NewInputBytes(src[:len(src):len(src)]), false)
	sawRule := false
	for {
		grammar, _, _ := p.Next()
		switch grammar {
		case css.ErrorGrammar:
			return p.Err() == io.EOF && sawRule
		case css.AtRuleGrammar, css.BeginAtRuleGrammar:
			sawRule = true
		case css.BeginRulesetGrammar:
			if !plausibleCSSSelector(p.Values()) {
				return false
			}
			sawRule = true
		}
	}
}

// The CSS grammar parser accepts arbitrary selector tokens. Reject JS
// assignments and calls rather than treating their blocks as style rules.
func plausibleCSSSelector(tokens []css.Token) bool {
	brackets, functions := 0, 0
	previous := css.EmptyToken
	for _, token := range tokens {
		switch token.TokenType {
		case css.WhitespaceToken, css.CommentToken:
			continue
		case css.LeftBracketToken:
			brackets++
		case css.RightBracketToken:
			brackets--
		case css.FunctionToken:
			if previous != css.ColonToken && functions == 0 {
				return false
			}
			functions++
		case css.LeftParenthesisToken:
			if functions == 0 {
				return false
			}
			functions++
		case css.RightParenthesisToken:
			functions--
		case css.DelimToken:
			if brackets == 0 && !bytes.ContainsAny(token.Data, ".*>+~|&") {
				return false
			}
		case css.SemicolonToken, css.AtKeywordToken:
			return false
		}
		previous = token.TokenType
	}
	return true
}

func completeCSSTokens(src []byte) bool {
	l := css.NewLexer(parse.NewInputBytes(src[:len(src):len(src)]))
	var closes []css.TokenType
	for {
		token, data := l.Next()
		switch token {
		case css.ErrorToken:
			return l.Err() == io.EOF && len(closes) == 0
		case css.BadStringToken, css.BadURLToken:
			return false
		case css.StringToken:
			if len(data) < 2 || data[len(data)-1] != data[0] {
				return false
			}
		case css.CommentToken:
			if !bytes.HasSuffix(data, []byte("*/")) {
				return false
			}
		case css.URLToken:
			if !bytes.HasSuffix(data, []byte(")")) {
				return false
			}
		case css.LeftBraceToken:
			closes = append(closes, css.RightBraceToken)
		case css.LeftBracketToken:
			closes = append(closes, css.RightBracketToken)
		case css.LeftParenthesisToken, css.FunctionToken:
			closes = append(closes, css.RightParenthesisToken)
		case css.RightBraceToken, css.RightBracketToken, css.RightParenthesisToken:
			if len(closes) == 0 || closes[len(closes)-1] != token {
				return false
			}
			closes = closes[:len(closes)-1]
		}
	}
}

// Catalog strings can contain entire JavaScript programs. Require every
// non-comment line to be a gettext directive or a quoted continuation, so a
// catalog-like prefix cannot discard a trailing program or a parse failure.
func isTranslationCatalog(src []byte) bool {
	sawID, sawTranslation, inString := false, false, false
	for line := range strings.Lines(string(src)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != '"' {
			end := strings.IndexAny(line, " \t")
			if end < 0 {
				return false
			}
			key, value := line[:end], line[end:]
			switch {
			case key == "msgid":
				sawID = true
			case key == "msgstr":
				sawTranslation = true
			case strings.HasPrefix(key, "msgstr[") && strings.HasSuffix(key, "]"):
				index := key[len("msgstr[") : len(key)-1]
				if index == "" || strings.Trim(index, "0123456789") != "" {
					return false
				}
				sawTranslation = true
			case key == "msgctxt", key == "msgid_plural":
			default:
				return false
			}
			line = strings.TrimSpace(value)
			inString = true
		}
		if !inString || len(line) < 2 || line[0] != '"' {
			return false
		}
		if _, err := strconv.Unquote(line); err != nil {
			return false
		}
	}
	return sawID && sawTranslation
}
