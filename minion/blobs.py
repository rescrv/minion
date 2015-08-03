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

import hashlib
import os
import shutil
import tempfile
import threading

class BlobStore(object):

    def __init__(self, path):
        self.base = path
        self.lock = threading.Lock()

    def add(self, path):
        src = open(path, 'rb')
        tmp = tempfile.NamedTemporaryFile(prefix='blob-', dir=self.base)
        shutil.copyfileobj(src, tmp)
        tmp.flush()
        tmp.seek(0)
        sha256 = hashlib.sha256()
        for x in tmp:
            sha256.update(x)
        sha256 = sha256.hexdigest()
        with self.lock:
            dst = self._sha256path(sha256)
            if not os.path.exists(dst):
                if not os.path.exists(os.path.dirname(dst)):
                    os.makedirs(os.path.dirname(dst))
                os.link(tmp.name, dst)
            return sha256

    def cat(self, content):
        tmp = tempfile.NamedTemporaryFile(prefix='blob-', dir=self.base)
        tmp.write(content)
        tmp.flush()
        return self.add(tmp.name)

    def dump(self, sha256):
        return open(self._sha256path(sha256), 'rb').read()

    def has(self, sha256):
        path = self._sha256path(sha256)
        return os.path.exists(path) and os.path.isfile(path)

    def copy(self, sha256, path):
        shutil.copy(self._sha256path(sha256), path)

    def path(self, sha256):
        return self._sha256path(sha256)

    def read(self, sha256):
        return open(self._sha256path(sha256), 'rb').read()

    def _sha256path(self, sha256):
        a, b, c = sha256[0:2], sha256[2:4], sha256[4:]
        return os.path.join(self.base, a, b, c)
