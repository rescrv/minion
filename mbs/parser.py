# Copyright (c) 2014, Robert Escriva
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of this project nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import collections
import os.path
import re

import ply.lex
import ply.yacc

import mbs

class ParseError(Exception): pass

# Structures

FetchSource = collections.namedtuple('FetchSource', ('name', 'url', 'sha256'))
GitSource = collections.namedtuple('GitSource', ('name', 'url', 'branch'))

DockerfileProcess = collections.namedtuple('DockerfileProcess', ('name', 'path',
    'dependencies', 'soft', 'full', 'artifacts'))

# Utilities

def define_envvar(envvars, obj, this_path, this_lineno):
    if obj.var in envvars:
        prev_path, prev_lineno = envvars[obj.var]
        raise ParseError('environment variable "%s" defined at location %s:%d was previously defined at %s:%d' %
                         (obj.var, this_path, this_lineno, prev_path, prev_lineno))
    envvars[obj.var] = (this_path, this_lineno)

# Tokens

reserved = {
    'source': 'SOURCE',
    'fetch': 'FETCH',
    'sha256': 'SHA256',
    'git': 'GIT',
    'branch': 'BRANCH',
    'process': 'PROCESS',
    'dockerfile': 'DOCKERFILE',
    'dependencies': 'DEPENDENCIES',
    'artifacts': 'ARTIFACTS',
    'soft': 'SOFT',
    'full': 'FULL',
}

tokens = (
    'SEMICOLON',
    'COMMA',
    'ARROW',
    'SHA256SUM',
    'URL',
    'IDENTIFIER',
) + tuple(reserved.values())

t_ignore = " \t"

def t_SEMICOLON(t):
    r';'
    return t

def t_COMMA(t):
    r','
    return t

def t_ARROW(t):
    r'=>'
    return t

def t_comment(t):
    r'\#[^\n]*'

def t_SHA256SUM(t):
    r'[0-9a-f]{64}'
    return t

def t_URL(t):
    r'(http|https|ftp|ssh|git)://[^\n \t;\#]+'
    return t

def t_IDENTIFIER(t):
    r'[a-zA-Z_][-:a-zA-Z0-9_/.]*'
    t.type = reserved.get(t.value, 'IDENTIFIER')
    return t

def t_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")

def t_error(t):
    raise ParseError('%s:%d: syntax error near "%s"' %
                 (t.lexer.path, t.lexer.lineno, t.value[:20].strip()))

# Grammar

def p_statements(t):
    '''
    stmts :
          | stmt SEMICOLON stmts
    '''
    if len(t) == 1:
        t[0] = []
    elif len(t) == 4:
        t[0] = [t[1]] + t[3]
    else:
        assert False

def p_statement(t):
    '''
    stmt : source
         | process
    '''
    t[0] = t[1]

def p_source(t):
    '''
    source : source_static
           | source_git
    '''
    define_envvar(t.lexer.envvars, t[1].name, t.lexer.path, t.lexer.lineno)
    t.lexer.sources.add(t[1].name)
    t[0] = t[1]

def p_source_static(t):
    '''
    source_static : SOURCE IDENTIFIER FETCH URL
                  | SOURCE IDENTIFIER FETCH URL SHA256 SHA256SUM
    '''
    if len(t) == 5:
        t[0] = FetchSource(name=mbs.SourceIdentifier(t[2]), url=t[4], sha256=None)
    elif len(t) == 7:
        t[0] = FetchSource(name=mbs.SourceIdentifier(t[2]), url=t[4], sha256=t[6])
    else:
        assert False

def p_source_git(t):
    '''
    source_git : SOURCE IDENTIFIER GIT URL
               | SOURCE IDENTIFIER GIT URL BRANCH IDENTIFIER
    '''
    if len(t) == 5:
        t[0] = GitSource(name=mbs.SourceIdentifier(t[2]), url=t[4], branch='master')
    elif len(t) == 7:
        t[0] = GitSource(name=mbs.SourceIdentifier(t[2]), url=t[4], branch=t[6])
    else:
        assert False

def p_process(t):
    '''
    process : process_dockerfile
    '''
    t[0] = t[1]

class Soft(object):
    def __init__(self, x):
        self.dep = x

class Full(object):
    def __init__(self, x):
        self.dep = x

class SoftFull(Soft, Full):
    def __init__(self, x):
        super(SoftFull, self).__init__(x)

def p_process_dockerfile(t):
    '''
    process_dockerfile : PROCESS IDENTIFIER DOCKERFILE IDENTIFIER
                       | PROCESS IDENTIFIER DOCKERFILE IDENTIFIER DEPENDENCIES dependency_list
                       | PROCESS IDENTIFIER DOCKERFILE IDENTIFIER ARTIFACTS artifact_list
                       | PROCESS IDENTIFIER DOCKERFILE IDENTIFIER DEPENDENCIES dependency_list ARTIFACTS artifact_list
    '''
    name = mbs.ProcessIdentifier(t[2])
    path = t[4]
    dependencies = ()
    soft = ()
    full = ()
    artifacts = ()
    if (len(t) == 7 and t[5] == 'dependencies') or len(t) == 9:
        soft = tuple([x.dep for x in t[6] if isinstance(x, Soft)])
        full = tuple([x.dep for x in t[6] if isinstance(x, Full)])
        def iswrapper(x):
            return isinstance(x, Soft) or isinstance(x, Full)
        dependencies = tuple([(x.dep if iswrapper(x) else x) for x in t[6]])
    if len(t) == 7 and t[5] == 'artifacts':
        artifacts = t[6]
    if len(t) == 9:
        artifacts = t[8]
    def dep(d):
        if isinstance(d, tuple):
            return mbs.ArtifactIdentifier(d[0], d[1])
        else:
            return mbs.SourceIdentifier(d)
    dependencies = tuple([dep(d) for d in dependencies])
    soft = tuple([dep(d) for d in soft])
    full = tuple([dep(d) for d in full])
    artifacts = tuple([mbs.ArtifactIdentifier(str(name), a) for a in artifacts])
    define_envvar(t.lexer.envvars, name, t.lexer.path, t.lexer.lineno)
    for d in dependencies:
        if isinstance(d, mbs.ArtifactIdentifier):
            if d not in t.lexer.artifacts:
                raise RuntimeError("process %s depends on unknown artifact %s" % (name, d))
        if isinstance(d, mbs.SourceIdentifier):
            if d not in t.lexer.sources:
                raise RuntimeError("process %s depends on unknown source %s" % (name, d))
    for a in artifacts:
        define_envvar(t.lexer.envvars, a, t.lexer.path, t.lexer.lineno)
    for a in artifacts:
        t.lexer.artifacts.add(a)
    t[0] = DockerfileProcess(name=name, path=path, dependencies=dependencies,
            soft=soft, full=full, artifacts=artifacts)

def p_dependency_list(t):
    '''
    dependency_list : dependency
                    | dependency COMMA dependency_list
    '''
    if len(t) == 2:
        t[0] = (t[1],)
    elif len(t) == 4:
        t[0] = (t[1],) + t[3]
    else:
        assert False

def p_dependency(t):
    '''
    dependency : IDENTIFIER
               | SOFT IDENTIFIER
               | FULL IDENTIFIER
               | SOFT FULL IDENTIFIER
               | FULL SOFT IDENTIFIER
               | IDENTIFIER ARROW IDENTIFIER
               | SOFT IDENTIFIER ARROW IDENTIFIER
               | FULL IDENTIFIER ARROW IDENTIFIER
               | SOFT FULL IDENTIFIER ARROW IDENTIFIER
               | FULL SOFT IDENTIFIER ARROW IDENTIFIER
    '''
    if len(t) == 2:
        t[0] = t[1]
    elif len(t) == 3 and t[1] == 'soft':
        t[0] = Soft(t[2])
    elif len(t) == 3 and t[1] == 'full':
        t[0] = Full(t[2])
    elif len(t) == 4 and t[1] in ('soft', 'full'):
        t[0] = SoftFull(t[3])
    elif len(t) == 4:
        t[0] = (t[1], t[3])
    elif len(t) == 5 and t[1] == 'soft':
        t[0] = Soft((t[2], t[4]))
    elif len(t) == 5 and t[1] == 'full':
        t[0] = Full((t[2], t[4]))
    elif len(t) == 6:
        t[0] = SoftFull((t[3], t[5]))
    else:
        print(len(t), tuple(t))
        assert False

def p_artifact_list(t):
    '''
    artifact_list : IDENTIFIER
                  | IDENTIFIER COMMA artifact_list
    '''
    if len(t) == 2:
        t[0] = (t[1],)
    elif len(t) == 4:
        t[0] = (t[1],) + t[3]
    else:
        assert False

def p_error(t):
    if t is None:
        raise ParseError('unexpected end of file')
    else:
        raise ParseError('%s:%d: syntax error near "%s"' %
                     (t.lexer.path, t.lexer.lineno, t.value[:20].strip()))

# Public Functions

def parse(filename):
    f = open(filename)
    contents = f.read()
    lexer = ply.lex.lex(reflags=re.UNICODE)
    lexer.path = filename
    lexer.file = os.path.basename(filename)
    lexer.lineno = 1
    lexer.expectstring = False
    lexer.envvars = {}
    lexer.sources = set()
    lexer.artifacts = set()
    parser = ply.yacc.yacc(debug=0, write_tables=0)
    return parser.parse(contents, lexer=lexer)
