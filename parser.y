%{

package minion

import (
    "errors"
)

%}

%union {
    mf    Minionfile
    src   Source
    proc  Process
    deps  []Dependency
    dep   Dependency
    slist []string
    tok   token
}

%token SEMICOLON
%token COMMA
%token ARROW
%token SHA256SUM
%token URL
%token IDENTIFIER
%token SOURCE
%token FETCH
%token SHA256
%token GIT
%token BRANCH
%token PROCESS
%token DOCKERFILE
%token DEPENDENCIES
%token ARTIFACTS
%token SOFT
%token FULL

%type <mf> stmts
%type <mf> stmt

%type <src> source
%type <src> source_static
%type <src> source_git

%type <proc> process
%type <proc> process_dockerfile

%type <deps> dependency_list
%type <dep> dependency

%type <slist> artifact_list

%type <tok> IDENTIFIER
%type <tok> URL
%type <tok> SHA256SUM

%%

stmts :
    {
        $$ = Minionfile{[]Process{}, []Source{}}
        parserlex.(*parserLex).mf = $$
    }

stmts : stmt SEMICOLON stmts
    {
        procs := $1.Processes
        procs = append(procs, $3.Processes...)
        srcs := $1.Sources
        srcs = append(srcs, $3.Sources...)
        $$ = Minionfile{procs, srcs}
        parserlex.(*parserLex).mf = $$
    }

stmt : source
    {
        $$ = Minionfile{[]Process{}, []Source{$1}}
    }

stmt : process
    {
        $$ = Minionfile{[]Process{$1}, []Source{}}
    }

source : source_static
       | source_git
    {
        $$ = $1
    }

source_static : SOURCE IDENTIFIER FETCH URL
    {
        $$ = NewFetchSource($2.val, $4.val, "")
    }
source_static : SOURCE IDENTIFIER FETCH URL SHA256 SHA256SUM
    {
        $$ = NewFetchSource($2.val, $4.val, $6.val)
    }

source_git : SOURCE IDENTIFIER GIT URL
    {
        $$ = NewGitSource($2.val, $4.val, "master")
    }

source_git : SOURCE IDENTIFIER GIT URL BRANCH IDENTIFIER
    {
        $$ = NewGitSource($2.val, $4.val, $6.val)
    }

process : process_dockerfile
    {
        $$ = $1
    }

process_dockerfile : PROCESS IDENTIFIER DOCKERFILE IDENTIFIER
    {
        deps := []Dependency{}
        arts := []string{}
        $$ = NewDockerfileProcess($2.val, $4.val, deps, arts)
    }

process_dockerfile : PROCESS IDENTIFIER DOCKERFILE IDENTIFIER DEPENDENCIES dependency_list
    {
        arts := []string{}
        $$ = NewDockerfileProcess($2.val, $4.val, $6, arts)
    }

process_dockerfile : PROCESS IDENTIFIER DOCKERFILE IDENTIFIER ARTIFACTS artifact_list
    {
        deps := []Dependency{}
        $$ = NewDockerfileProcess($2.val, $4.val, deps, $6)
    }

process_dockerfile : PROCESS IDENTIFIER DOCKERFILE IDENTIFIER DEPENDENCIES dependency_list ARTIFACTS artifact_list
    {
        $$ = NewDockerfileProcess($2.val, $4.val, $6, $8)
    }

dependency_list : dependency
    {
        $$ = []Dependency{$1}
    }

dependency_list : dependency COMMA dependency_list
    {
        deps := []Dependency{$1}
        $$ = append(deps, $3...)
    }

dependency : IDENTIFIER
    {
        $$ = NewSourceDependency($1.val, false, false)
    }

dependency : SOFT IDENTIFIER
    {
        $$ = NewSourceDependency($2.val, true, false)
    }

dependency : FULL IDENTIFIER
    {
        $$ = NewSourceDependency($2.val, false, true)
    }

dependency : SOFT FULL IDENTIFIER
    {
        $$ = NewSourceDependency($3.val, true, true)
    }

dependency : FULL SOFT IDENTIFIER
    {
        $$ = NewSourceDependency($3.val, true, true)
    }

dependency : IDENTIFIER ARROW IDENTIFIER
    {
        $$ = NewArtifactDependency($1.val, $3.val, false, false)
    }

dependency : SOFT IDENTIFIER ARROW IDENTIFIER
    {
        $$ = NewArtifactDependency($2.val, $4.val, true, false)
    }

dependency : FULL IDENTIFIER ARROW IDENTIFIER
    {
        $$ = NewArtifactDependency($2.val, $4.val, false, true)
    }

dependency : SOFT FULL IDENTIFIER ARROW IDENTIFIER
    {
        $$ = NewArtifactDependency($3.val, $5.val, true, true)
    }

dependency : FULL SOFT IDENTIFIER ARROW IDENTIFIER
    {
        $$ = NewArtifactDependency($3.val, $5.val, true, true)
    }

artifact_list : IDENTIFIER
    {
        $$ = []string{$1.val}
    }

artifact_list : IDENTIFIER COMMA artifact_list
    {
        arts := []string{$1.val}
        $$ = append(arts, $3...)
    }

%%

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
