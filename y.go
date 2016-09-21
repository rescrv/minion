//line parser.y:2
package minion

import __yyfmt__ "fmt"

//line parser.y:3
import (
	"errors"
)

//line parser.y:11
type parserSymType struct {
	yys   int
	mf    Minionfile
	src   Source
	proc  Process
	deps  []Dependency
	dep   Dependency
	slist []string
	tok   token
}

const SEMICOLON = 57346
const COMMA = 57347
const ARROW = 57348
const SHA256SUM = 57349
const URL = 57350
const IDENTIFIER = 57351
const SOURCE = 57352
const FETCH = 57353
const SHA256 = 57354
const GIT = 57355
const BRANCH = 57356
const PROCESS = 57357
const DOCKERFILE = 57358
const DEPENDENCIES = 57359
const ARTIFACTS = 57360
const SOFT = 57361
const FULL = 57362

var parserToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"SEMICOLON",
	"COMMA",
	"ARROW",
	"SHA256SUM",
	"URL",
	"IDENTIFIER",
	"SOURCE",
	"FETCH",
	"SHA256",
	"GIT",
	"BRANCH",
	"PROCESS",
	"DOCKERFILE",
	"DEPENDENCIES",
	"ARTIFACTS",
	"SOFT",
	"FULL",
}
var parserStatenames = [...]string{}

const parserEofCode = 1
const parserErrCode = 2
const parserInitialStackSize = 16

//line parser.y:212
type parserLex struct {
	lexer *Lexer
	mf    Minionfile
}

func (x parserLex) Lex(yylval *parserSymType) int {
	yylval.tok = x.lexer.Next()
	return yylval.tok.typ
}

func (x parserLex) Error(s string) {
	panic(errors.New(s))
}

//line yacctab:1
var parserExca = [...]int{
	-1, 1,
	1, -1,
	-2, 0,
}

const parserNprod = 30
const parserPrivate = 57344

var parserTokenNames []string
var parserStates []string

const parserLast = 54

var parserAct = [...]int{

	31, 26, 28, 36, 33, 38, 22, 23, 16, 21,
	20, 8, 29, 30, 37, 39, 9, 14, 1, 15,
	54, 53, 51, 49, 32, 47, 45, 43, 25, 13,
	19, 12, 11, 18, 41, 17, 42, 24, 52, 50,
	46, 48, 44, 35, 40, 34, 10, 27, 7, 4,
	6, 5, 3, 2,
}
var parserPact = [...]int{

	1, -1000, 42, -1000, -1000, -1000, -1000, -1000, 23, 22,
	1, 6, -8, -1000, 27, 25, 21, -2, -5, -11,
	30, 19, -7, 15, -1000, -1000, -14, 40, 37, -6,
	-4, -1000, 39, 15, -7, 18, 36, 17, 34, 16,
	15, -1000, -1000, -1000, 14, 33, 13, 32, -1000, -1000,
	12, -1000, 11, -1000, -1000,
}
var parserPgo = [...]int{

	0, 18, 53, 52, 51, 50, 49, 48, 1, 47,
	0,
}
var parserR1 = [...]int{

	0, 1, 1, 2, 2, 3, 3, 4, 4, 5,
	5, 6, 7, 7, 7, 7, 8, 8, 9, 9,
	9, 9, 9, 9, 9, 9, 9, 9, 10, 10,
}
var parserR2 = [...]int{

	0, 0, 3, 1, 1, 1, 1, 4, 6, 4,
	6, 1, 4, 6, 6, 8, 1, 3, 1, 2,
	2, 3, 3, 3, 4, 4, 5, 5, 1, 3,
}
var parserChk = [...]int{

	-1000, -1, -2, -3, -6, -4, -5, -7, 10, 15,
	4, 9, 9, -1, 11, 13, 16, 8, 8, 9,
	12, 14, 17, 18, 7, 9, -8, -9, 9, 19,
	20, -10, 9, 18, 5, 6, 9, 20, 9, 19,
	5, -10, -8, 9, 6, 9, 6, 9, -10, 9,
	6, 9, 6, 9, 9,
}
var parserDef = [...]int{

	1, -2, 0, 3, 4, 5, 6, 11, 0, 0,
	1, 0, 0, 2, 0, 0, 0, 7, 9, 12,
	0, 0, 0, 0, 8, 10, 13, 16, 18, 0,
	0, 14, 28, 0, 0, 0, 19, 0, 20, 0,
	0, 15, 17, 23, 0, 21, 0, 22, 29, 24,
	0, 25, 0, 26, 27,
}
var parserTok1 = [...]int{

	1,
}
var parserTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20,
}
var parserTok3 = [...]int{
	0,
}

var parserErrorMessages = [...]struct {
	state int
	token int
	msg   string
}{}

//line yaccpar:1

/*	parser for yacc output	*/

var (
	parserDebug        = 0
	parserErrorVerbose = false
)

type parserLexer interface {
	Lex(lval *parserSymType) int
	Error(s string)
}

type parserParser interface {
	Parse(parserLexer) int
	Lookahead() int
}

type parserParserImpl struct {
	lval  parserSymType
	stack [parserInitialStackSize]parserSymType
	char  int
}

func (p *parserParserImpl) Lookahead() int {
	return p.char
}

func parserNewParser() parserParser {
	return &parserParserImpl{}
}

const parserFlag = -1000

func parserTokname(c int) string {
	if c >= 1 && c-1 < len(parserToknames) {
		if parserToknames[c-1] != "" {
			return parserToknames[c-1]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func parserStatname(s int) string {
	if s >= 0 && s < len(parserStatenames) {
		if parserStatenames[s] != "" {
			return parserStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func parserErrorMessage(state, lookAhead int) string {
	const TOKSTART = 4

	if !parserErrorVerbose {
		return "syntax error"
	}

	for _, e := range parserErrorMessages {
		if e.state == state && e.token == lookAhead {
			return "syntax error: " + e.msg
		}
	}

	res := "syntax error: unexpected " + parserTokname(lookAhead)

	// To match Bison, suggest at most four expected tokens.
	expected := make([]int, 0, 4)

	// Look for shiftable tokens.
	base := parserPact[state]
	for tok := TOKSTART; tok-1 < len(parserToknames); tok++ {
		if n := base + tok; n >= 0 && n < parserLast && parserChk[parserAct[n]] == tok {
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}
	}

	if parserDef[state] == -2 {
		i := 0
		for parserExca[i] != -1 || parserExca[i+1] != state {
			i += 2
		}

		// Look for tokens that we accept or reduce.
		for i += 2; parserExca[i] >= 0; i += 2 {
			tok := parserExca[i]
			if tok < TOKSTART || parserExca[i+1] == 0 {
				continue
			}
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}

		// If the default action is to accept or reduce, give up.
		if parserExca[i+1] != 0 {
			return res
		}
	}

	for i, tok := range expected {
		if i == 0 {
			res += ", expecting "
		} else {
			res += " or "
		}
		res += parserTokname(tok)
	}
	return res
}

func parserlex1(lex parserLexer, lval *parserSymType) (char, token int) {
	token = 0
	char = lex.Lex(lval)
	if char <= 0 {
		token = parserTok1[0]
		goto out
	}
	if char < len(parserTok1) {
		token = parserTok1[char]
		goto out
	}
	if char >= parserPrivate {
		if char < parserPrivate+len(parserTok2) {
			token = parserTok2[char-parserPrivate]
			goto out
		}
	}
	for i := 0; i < len(parserTok3); i += 2 {
		token = parserTok3[i+0]
		if token == char {
			token = parserTok3[i+1]
			goto out
		}
	}

out:
	if token == 0 {
		token = parserTok2[1] /* unknown char */
	}
	if parserDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", parserTokname(token), uint(char))
	}
	return char, token
}

func parserParse(parserlex parserLexer) int {
	return parserNewParser().Parse(parserlex)
}

func (parserrcvr *parserParserImpl) Parse(parserlex parserLexer) int {
	var parsern int
	var parserVAL parserSymType
	var parserDollar []parserSymType
	_ = parserDollar // silence set and not used
	parserS := parserrcvr.stack[:]

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	parserstate := 0
	parserrcvr.char = -1
	parsertoken := -1 // parserrcvr.char translated into internal numbering
	defer func() {
		// Make sure we report no lookahead when not parsing.
		parserstate = -1
		parserrcvr.char = -1
		parsertoken = -1
	}()
	parserp := -1
	goto parserstack

ret0:
	return 0

ret1:
	return 1

parserstack:
	/* put a state and value onto the stack */
	if parserDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", parserTokname(parsertoken), parserStatname(parserstate))
	}

	parserp++
	if parserp >= len(parserS) {
		nyys := make([]parserSymType, len(parserS)*2)
		copy(nyys, parserS)
		parserS = nyys
	}
	parserS[parserp] = parserVAL
	parserS[parserp].yys = parserstate

parsernewstate:
	parsern = parserPact[parserstate]
	if parsern <= parserFlag {
		goto parserdefault /* simple state */
	}
	if parserrcvr.char < 0 {
		parserrcvr.char, parsertoken = parserlex1(parserlex, &parserrcvr.lval)
	}
	parsern += parsertoken
	if parsern < 0 || parsern >= parserLast {
		goto parserdefault
	}
	parsern = parserAct[parsern]
	if parserChk[parsern] == parsertoken { /* valid shift */
		parserrcvr.char = -1
		parsertoken = -1
		parserVAL = parserrcvr.lval
		parserstate = parsern
		if Errflag > 0 {
			Errflag--
		}
		goto parserstack
	}

parserdefault:
	/* default state action */
	parsern = parserDef[parserstate]
	if parsern == -2 {
		if parserrcvr.char < 0 {
			parserrcvr.char, parsertoken = parserlex1(parserlex, &parserrcvr.lval)
		}

		/* look through exception table */
		xi := 0
		for {
			if parserExca[xi+0] == -1 && parserExca[xi+1] == parserstate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			parsern = parserExca[xi+0]
			if parsern < 0 || parsern == parsertoken {
				break
			}
		}
		parsern = parserExca[xi+1]
		if parsern < 0 {
			goto ret0
		}
	}
	if parsern == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			parserlex.Error(parserErrorMessage(parserstate, parsertoken))
			Nerrs++
			if parserDebug >= 1 {
				__yyfmt__.Printf("%s", parserStatname(parserstate))
				__yyfmt__.Printf(" saw %s\n", parserTokname(parsertoken))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for parserp >= 0 {
				parsern = parserPact[parserS[parserp].yys] + parserErrCode
				if parsern >= 0 && parsern < parserLast {
					parserstate = parserAct[parsern] /* simulate a shift of "error" */
					if parserChk[parserstate] == parserErrCode {
						goto parserstack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if parserDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", parserS[parserp].yys)
				}
				parserp--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if parserDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", parserTokname(parsertoken))
			}
			if parsertoken == parserEofCode {
				goto ret1
			}
			parserrcvr.char = -1
			parsertoken = -1
			goto parsernewstate /* try again in the same state */
		}
	}

	/* reduction by production parsern */
	if parserDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", parsern, parserStatname(parserstate))
	}

	parsernt := parsern
	parserpt := parserp
	_ = parserpt // guard against "declared and not used"

	parserp -= parserR2[parsern]
	// parserp is now the index of $0. Perform the default action. Iff the
	// reduced production is ε, $1 is possibly out of range.
	if parserp+1 >= len(parserS) {
		nyys := make([]parserSymType, len(parserS)*2)
		copy(nyys, parserS)
		parserS = nyys
	}
	parserVAL = parserS[parserp+1]

	/* consult goto table to find next state */
	parsern = parserR1[parsern]
	parserg := parserPgo[parsern]
	parserj := parserg + parserS[parserp].yys + 1

	if parserj >= parserLast {
		parserstate = parserAct[parserg]
	} else {
		parserstate = parserAct[parserj]
		if parserChk[parserstate] != -parsern {
			parserstate = parserAct[parserg]
		}
	}
	// dummy call; replaced with literal code
	switch parsernt {

	case 1:
		parserDollar = parserS[parserpt-0 : parserpt+1]
		//line parser.y:61
		{
			parserVAL.mf = Minionfile{[]Process{}, []Source{}}
			parserlex.(*parserLex).mf = parserVAL.mf
		}
	case 2:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:67
		{
			procs := parserDollar[1].mf.Processes
			procs = append(procs, parserDollar[3].mf.Processes...)
			srcs := parserDollar[1].mf.Sources
			srcs = append(srcs, parserDollar[3].mf.Sources...)
			parserVAL.mf = Minionfile{procs, srcs}
			parserlex.(*parserLex).mf = parserVAL.mf
		}
	case 3:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:77
		{
			parserVAL.mf = Minionfile{[]Process{}, []Source{parserDollar[1].src}}
		}
	case 4:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:82
		{
			parserVAL.mf = Minionfile{[]Process{parserDollar[1].proc}, []Source{}}
		}
	case 6:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:88
		{
			parserVAL.src = parserDollar[1].src
		}
	case 7:
		parserDollar = parserS[parserpt-4 : parserpt+1]
		//line parser.y:93
		{
			parserVAL.src = NewFetchSource(parserDollar[2].tok.val, parserDollar[4].tok.val, "")
		}
	case 8:
		parserDollar = parserS[parserpt-6 : parserpt+1]
		//line parser.y:97
		{
			parserVAL.src = NewFetchSource(parserDollar[2].tok.val, parserDollar[4].tok.val, parserDollar[6].tok.val)
		}
	case 9:
		parserDollar = parserS[parserpt-4 : parserpt+1]
		//line parser.y:102
		{
			parserVAL.src = NewGitSource(parserDollar[2].tok.val, parserDollar[4].tok.val, "master")
		}
	case 10:
		parserDollar = parserS[parserpt-6 : parserpt+1]
		//line parser.y:107
		{
			parserVAL.src = NewGitSource(parserDollar[2].tok.val, parserDollar[4].tok.val, parserDollar[6].tok.val)
		}
	case 11:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:112
		{
			parserVAL.proc = parserDollar[1].proc
		}
	case 12:
		parserDollar = parserS[parserpt-4 : parserpt+1]
		//line parser.y:117
		{
			deps := []Dependency{}
			arts := []string{}
			parserVAL.proc = NewDockerfileProcess(parserDollar[2].tok.val, parserDollar[4].tok.val, deps, arts)
		}
	case 13:
		parserDollar = parserS[parserpt-6 : parserpt+1]
		//line parser.y:124
		{
			arts := []string{}
			parserVAL.proc = NewDockerfileProcess(parserDollar[2].tok.val, parserDollar[4].tok.val, parserDollar[6].deps, arts)
		}
	case 14:
		parserDollar = parserS[parserpt-6 : parserpt+1]
		//line parser.y:130
		{
			deps := []Dependency{}
			parserVAL.proc = NewDockerfileProcess(parserDollar[2].tok.val, parserDollar[4].tok.val, deps, parserDollar[6].slist)
		}
	case 15:
		parserDollar = parserS[parserpt-8 : parserpt+1]
		//line parser.y:136
		{
			parserVAL.proc = NewDockerfileProcess(parserDollar[2].tok.val, parserDollar[4].tok.val, parserDollar[6].deps, parserDollar[8].slist)
		}
	case 16:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:141
		{
			parserVAL.deps = []Dependency{parserDollar[1].dep}
		}
	case 17:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:146
		{
			deps := []Dependency{parserDollar[1].dep}
			parserVAL.deps = append(deps, parserDollar[3].deps...)
		}
	case 18:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:152
		{
			parserVAL.dep = NewSourceDependency(parserDollar[1].tok.val, false, false)
		}
	case 19:
		parserDollar = parserS[parserpt-2 : parserpt+1]
		//line parser.y:157
		{
			parserVAL.dep = NewSourceDependency(parserDollar[2].tok.val, true, false)
		}
	case 20:
		parserDollar = parserS[parserpt-2 : parserpt+1]
		//line parser.y:162
		{
			parserVAL.dep = NewSourceDependency(parserDollar[2].tok.val, false, true)
		}
	case 21:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:167
		{
			parserVAL.dep = NewSourceDependency(parserDollar[3].tok.val, true, true)
		}
	case 22:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:172
		{
			parserVAL.dep = NewSourceDependency(parserDollar[3].tok.val, true, true)
		}
	case 23:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:177
		{
			parserVAL.dep = NewArtifactDependency(parserDollar[1].tok.val, parserDollar[3].tok.val, false, false)
		}
	case 24:
		parserDollar = parserS[parserpt-4 : parserpt+1]
		//line parser.y:182
		{
			parserVAL.dep = NewArtifactDependency(parserDollar[2].tok.val, parserDollar[4].tok.val, true, false)
		}
	case 25:
		parserDollar = parserS[parserpt-4 : parserpt+1]
		//line parser.y:187
		{
			parserVAL.dep = NewArtifactDependency(parserDollar[2].tok.val, parserDollar[4].tok.val, false, true)
		}
	case 26:
		parserDollar = parserS[parserpt-5 : parserpt+1]
		//line parser.y:192
		{
			parserVAL.dep = NewArtifactDependency(parserDollar[3].tok.val, parserDollar[5].tok.val, true, true)
		}
	case 27:
		parserDollar = parserS[parserpt-5 : parserpt+1]
		//line parser.y:197
		{
			parserVAL.dep = NewArtifactDependency(parserDollar[3].tok.val, parserDollar[5].tok.val, true, true)
		}
	case 28:
		parserDollar = parserS[parserpt-1 : parserpt+1]
		//line parser.y:202
		{
			parserVAL.slist = []string{parserDollar[1].tok.val}
		}
	case 29:
		parserDollar = parserS[parserpt-3 : parserpt+1]
		//line parser.y:207
		{
			arts := []string{parserDollar[1].tok.val}
			parserVAL.slist = append(arts, parserDollar[3].slist...)
		}
	}
	goto parserstack /* stack new state and value */
}
