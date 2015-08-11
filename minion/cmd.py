# Copyright (c) 2015, Robert Escriva
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

def update_heads(parser):
    parser.add_argument('sources', metavar='SOURCE', type=str, nargs='*',
                        help='the list of sources to update')
    return parser

def new_target(parser):
    parser.add_argument('target', type=str, help='name of the new target')
    return parser

def del_target(parser):
    parser.add_argument('target', type=str, help='name of the target to remove')
    return parser

def set_refspec(parser):
    parser.add_argument('target', type=str, help='name of the target to remove')
    parser.add_argument('source', type=str, help='the sources to update')
    parser.add_argument('refspec', type=str, help='the refspect to set')
    return parser

def build(parser):
    parser.add_argument('--name', type=str, default=None,
                        help='name to use when saving this report')
    parser.add_argument('--processes', type=str,
                        help='name to use when saving this report')
    parser.add_argument('--retry-failures', action='store_true', default=False)
    parser.add_argument('target', type=str, help='name of the target to build')
    return parser

def status(parser):
    parser.add_argument('--name', type=str, default=None,
                        help='name of the build (defaults to the latest)')
    parser.add_argument('--report', type=str, choices=('abbrev', 'short', 'long', 'full', 'failed', 'docker-images'),
                        default='long', help='type of report to generate')
    parser.add_argument('target', type=str, help='name of the target to check')
    return parser

def add_blob(parser):
    parser.add_argument('blobs', metavar='BLOB', type=str, nargs='*',
                        help='the list of files to add to the blob pool')
    return parser
