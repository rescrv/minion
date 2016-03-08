# Copyright (c) 2014-2016, Robert Escriva
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

import argparse
import binascii
import collections
import datetime
import errno
import fcntl
import fnmatch
import hashlib
import json
import logging
import mimetypes
import os
import os.path
import queue
import re
import shlex
import shutil
import socket
import string
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request

import flask
from flask import render_template
from flask import request
from flask import Response

import mbs.blobs
import mbs.parser

class MinionError(Exception): pass

class Identifier(object):

    def __init__(self, name):
        self.name = name

    @property
    def var(self):
        return identifier_to_envvar(self.name, self.category)

    @property
    def normal(self):
        return normalize_identifier(self.name)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '%s(%s)' % (self.category.capitalize(), self.name)

    def __hash__(self):
        return hash(repr(self))

    def __eq__(self, other):
        return repr(self) == repr(other)

class SourceIdentifier(Identifier):

    @property
    def category(self):
        return 'source'

class ProcessIdentifier(Identifier):

    @property
    def category(self):
        return 'process'

class ArtifactIdentifier(object):

    def __init__(self, process, artifact):
        self.process = process
        self.artifact = artifact

    @property
    def var(self):
        return identifier_to_envvar(str(self), self.category)

    @property
    def category(self):
        return 'artifact'

    def __str__(self):
        return self.process + '=>' + self.artifact

    def __repr__(self):
        return '%s(%s=>%s)' % (self.category.capitalize(),
                self.process, self.artifact)

    def __hash__(self):
        return hash(repr(self))

    def __eq__(self, other):
        return repr(self) == repr(other)

def sha256sum(x):
    sha256 = hashlib.sha256()
    sha256.update(x)
    return sha256.hexdigest()

def normalize_identifier(identifier):
    def convert(c):
        if c in string.ascii_letters + string.digits:
            return c
        return '_'
    s = ''.join([convert(c) for c in identifier])
    pieces = s.split('_')
    return '_'.join([p for p in pieces if p])

def identifier_to_envvar(identifier, prefix=''):
    return normalize_identifier('MINION_' + prefix + '_' + identifier).upper()

def issource(x):
    return isinstance(x, mbs.parser.FetchSource) or isinstance(x, mbs.parser.GitSource)

def isgit(x):
    return isinstance(x, mbs.parser.GitSource)

def isprocess(x):
    return isdockerfileprocess(x)

def isdockerfileprocess(x):
    return isinstance(x, mbs.parser.DockerfileProcess)

def utcnow():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

def run(name, args, env=None, cwd=None):
    p = subprocess.Popen(args, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        raise MinionError(("%s failed:\n%s" % (name, stdout.decode('utf8', 'ignore'))).strip())
    return stdout

def run_no_fail(args, env=None):
    p = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = p.communicate()

class ProcessArtifactMap(object):

    def __init__(self, base):
        self.base = base

    def lookup(self, inputs_id):
        path = self._path(inputs_id)
        if not os.path.exists(path):
            return None
        return open(path).read().strip()

    def insert(self, inputs_id, outputs_id):
        path = self._path(inputs_id)
        dirn = os.path.dirname(path)
        if not os.path.exists(dirn):
            os.makedirs(dirn)
        tmp = tempfile.NamedTemporaryFile(prefix='tmp-', dir=self.base)
        outputs_id = outputs_id.strip() + '\n'
        tmp.write(outputs_id.encode('utf8'))
        tmp.flush()
        os.rename(tmp.name, path)
        os.link(path, tmp.name)
        tmp.close()

    def forget(self, inputs_id):
        x = self.lookup(inputs_id)
        os.unlink(self._path(inputs_id))

    def _path(self, sha256):
        assert len(sha256) == 64
        a, b, c = sha256[0:2], sha256[2:4], sha256[4:]
        return os.path.join(self.base, a, b, c)

################################## Build Jobs ##################################

def clone_repo(dep, gitrepos, where, refspec):
    repo = dep.normal
    try:
        run('git clone', ('git', 'clone', '--no-local', '--no-hardlinks',
                          os.path.join(gitrepos, repo),
                          os.path.join(where, repo)))
        run('git checkout', ('git', 'checkout', refspec),
                            cwd=os.path.join(where, repo))
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise MinionError("git binary not found (is it installed?)")
        raise e

class JobController(object):

    def __init__(self, minion, sources, name):
        self.minion = minion
        self.sources = sources.copy()
        self.name = name
        self.artifacts = {}
        self.processes = {}
        self.finished = set([])
        self.reports = []
        self.count = 0
        self.mtx = threading.Lock()
        self.cnd = threading.Condition(self.mtx)
        self.failed = -1
        self.retry_failures = False

    def success(self):
        return self.failed == self.count

    def add(self, proc):
        with self.mtx:
            assert isprocess(proc)
            assert proc.name not in self.processes
            if isdockerfileprocess(proc):
                self.processes[proc.name] = (self.count, DockerfileJobThread(self, proc))
                self.count += 1
            else:
                raise MinionError("no support for process %s" % proc.name)

    def run(self):
        with self.mtx:
            self.failed = self.count
            threads = [t for (name, (c, t)) in self.processes.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(self.reports) == len(self.processes)

    def get_inputs(self):
        with self.mtx:
            return self.sources.copy(), self.artifacts.copy()

    def wait_for(self, proc):
        with self.mtx:
            proc_count = self.processes[proc.name][0]
            def done():
                # funky if <pred>: return True just to improve readability of
                # disjunction
                if min([c for (name, (c, t)) in self.processes.items()
                        if name not in self.finished]) >= proc_count:
                    return True
                d = set([d for d in proc.dependencies if isinstance(d, ArtifactIdentifier)])
                a = set(self.artifacts.keys())
                if a.issuperset(d):
                    return True
                if self.failed < proc_count:
                    return True
                return False
            while not done():
                self.cnd.wait()
            d = set([d for d in proc.dependencies if isinstance(d, ArtifactIdentifier)])
            a = set(self.artifacts.keys())
            if self.failed > proc_count and (d & a) == d:
                return True
            else:
                return False

    def is_cached(self, stub):
        iid = self.minion.blobs.cat(stub)
        oid = self.minion.processes.lookup(iid)
        return oid is not None

    def read_output(self, proc, oid):
        # XXX compatibility stub to be removed later
        x = self.minion.outputs_read(proc, oid)
        return x['status'] == 'success', x['log'], x['artifacts']

    def get_cached(self, proc, stub):
        iid = self.minion.blobs.cat(stub)
        oid = self.minion.processes.lookup(iid)
        return self.read_output(proc, oid)

    def finish_cached(self, proc, stub, released=False):
        iid = self.minion.blobs.cat(stub)
        oid = self.minion.processes.lookup(iid)
        assert oid is not None
        success, log, artifacts = self.read_output(proc, oid)
        with self.mtx:
            self._report(proc, success, iid, oid,
                         artifacts=artifacts,
                         cached=True, released=released)

    def finish_bool(self, success, proc, stub, log, artifacts):
        if type(log) == bytes:
            log = log.decode('utf8', 'ignore')
        record = ''
        if success:
            record += 'Status: success\n'
        else:
            record += 'Status: failure\n'
        record += 'Log: %s\n' % self.minion.blobs.cat(log.encode('utf8', 'ignore'))
        if success:
            for a in proc.artifacts:
                assert a in artifacts
                sha256, path = artifacts[a]
                record += 'Artifact %s: %s %s\n' % (a, sha256, path)
        iid = self.minion.blobs.cat(stub)
        oid = self.minion.blobs.cat(record.encode('utf8'))
        with self.mtx:
            self.minion.processes.insert(iid, oid)
            self._report(proc, success, iid, oid, artifacts=artifacts)

    def finish_success(self, proc, stub, log, artifacts):
        return self.finish_bool(True, proc, stub, log, artifacts)

    def finish_error(self, proc, stub, log):
        return self.finish_bool(False, proc, stub, log, {})

    def finish_exception(self, proc, stub, e):
        self.abort_if_not_finished(proc)

    def abort_if_not_finished(self, proc):
        with self.mtx:
            if proc.name not in self.finished:
                self._report(proc, False, '-', '-')

    # with self.mtx held
    def _report(self, proc, success, iid, oid, artifacts=None, cached=False, released=False):
        assert proc.name not in self.finished
        self.finished.add(proc.name)
        if artifacts is not None:
            assert set(self.artifacts.keys()).isdisjoint(set(artifacts.keys()))
            self.artifacts.update(artifacts)
        self.cnd.notify_all()
        if not success:
            self.failed = self.processes[proc.name][0]
        idx = self.processes[proc.name][0]
        self.reports.append(Report(idx=idx, name=proc.name, success=success, inputs=iid, outputs=oid, cached=cached, released=released))
        self.reports.sort()

Report = collections.namedtuple('Report', ('idx', 'name', 'success', 'inputs', 'outputs', 'cached', 'released'))

class DockerfileJobThread(threading.Thread):

    def __init__(self, controller, proc):
        threading.Thread.__init__(self)
        self.controller = controller
        self.proc = proc

    def stub(self, sources, artifacts, image):
        deps = ''
        for d in self.proc.dependencies:
            if d in self.proc.soft:
                continue
            if isinstance(d, ArtifactIdentifier):
                assert d in artifacts
                deps += 'Dependency %s: %s\n' % (d, artifacts[d][0])
            elif isinstance(d, SourceIdentifier):
                if d.normal not in self.controller.sources:
                    raise MinionError("unknown source %s: try running auto-sources" % str(d))
                deps += 'Dependency %s: %s\n' % (d, sources[d.normal].split(' ')[0])
            else:
                assert False
        arts = ''
        for a in self.proc.artifacts:
            arts += 'Artifact %s\n' % a
        stub = '''Dockerfile
Process: %s
Image: %s
%s%s''' % (self.proc.name, image, deps, arts)
        stub = stub.encode('utf8')
        return stub

    def run(self):
        try:
            if not self.controller.wait_for(self.proc):
                return
            sources, artifacts = self.controller.get_inputs()
            stub = self.stub(sources, artifacts, '-')
            if self.controller.is_cached(stub):
                self.controller.finish_cached(self.proc, stub, released=True)
                return
            image = self.build_image(self.proc.path)
            stub = self.stub(sources, artifacts, image)
            if self.controller.is_cached(stub):
                success, X, X = self.controller.get_cached(self.proc, stub)
                if success or not self.controller.retry_failures:
                    self.controller.finish_cached(self.proc, stub)
                    return
            success, log, artifacts =  self.run_image(sources, artifacts, stub, image)
            if success:
                self.controller.finish_success(self.proc, stub, log, artifacts)
            else:
                self.controller.finish_error(self.proc, stub, log)
        finally:
            self.controller.abort_if_not_finished(self.proc)

    def build_image(self, path):
        try:
            img = run('docker build of %s' % path, ('docker', 'build', path),
                      cwd=self.controller.minion.BUILD)
            img = img.decode('utf8')
            m = re.search('Successfully built ([0-9A-Fa-f]+)', img)
            if not m:
                raise MinionError("docker build failed, but docker exited 0")
            return m.group(1)
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise MinionError("could not run docker (is it installed?)")
            raise e

    def run_image(self, sources, artifacts, stub, image):
        tmp = None
        try:
            tmp = tempfile.mkdtemp(prefix='minion-sources-', dir=self.controller.minion.workdir)
            env = {}
            for d in self.proc.dependencies:
                if isinstance(d, SourceIdentifier):
                    ptr = sources[d.normal].split(' ', 1)[0]
                    if len(ptr) == 40:
                        clone_repo(d, self.controller.minion.GITREPOS, tmp, ptr)
                        env[d.var] = os.path.join('/deps', d.normal)
                    elif len(ptr) == 64:
                        self.controller.minion.blobs.copy(ptr, os.path.join(tmp, str(d)))
                        env[d.var] = os.path.join('/deps', str(d))
                    else:
                        assert False
                if isinstance(d, ArtifactIdentifier):
                    sha256, name = artifacts[d]
                    intermediate = ''
                    if d in self.proc.full:
                        intermediate = d.process
                    dirn = os.path.join(tmp, intermediate)
                    if not os.path.exists(dirn):
                        os.makedirs(dirn)
                    self.controller.minion.blobs.copy(sha256, os.path.join(dirn, name))
                    env[d.var] = os.path.join('/deps', intermediate, name)
            name = sha256sum(stub + utcnow().encode('utf8'))
            env = [('-e', k + '=' + v) for k, v in sorted(env.items())]
            p = subprocess.Popen(('docker', 'run', '--privileged') + sum(env, ()) +
                                 ('--name', name, '-v', os.path.abspath(tmp) + ":/deps", image),
                                 cwd=self.controller.minion.BUILD,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            stdout, stderr = p.communicate()
            log = stdout.decode('utf8', 'ignore')
            if p.returncode != 0:
                return False, ("docker run of %s failed:\n" % self.proc.name) + log, {}
            new_artifacts = {}
            for k, v in re.findall('^(MINION_ARTIFACT_.*?)=(.*)$', stdout.decode('utf8', 'ignore'), re.MULTILINE):
                p = subprocess.Popen(('docker', 'cp', name + ':' + v, tmp),
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
                stdout, stderr = p.communicate()
                if p.returncode != 0:
                    return False, ("docker cp of %s failed:\n" % self.proc.name) + stdout.decode('utf8', 'ignore'), {}
                out = os.path.join(tmp, os.path.basename(v))
                new_artifacts[k] = (self.controller.minion.blobs.add(out), os.path.basename(v))
            new_artifacts_by_id = {}
            for a in self.proc.artifacts:
                if a.var not in new_artifacts:
                    return False, "process %s failed to produce artifact %s\n" % (self.proc.name, a) + log, {}
                new_artifacts_by_id[a] = new_artifacts[a.var]
            p = subprocess.Popen(('docker', 'rm', name),
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            p.communicate()
            ## don't care if failed; it just leaves garbage instances lying around
            return True, log, new_artifacts_by_id
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise MinionError("could not run docker (is it installed?)")
            raise e
        finally:
            if tmp is not None:
                shutil.rmtree(tmp)

################################# Minion Daemon ################################

class MinionDaemon(object):

    def __init__(self, workdir):
        self.workdir = workdir
        self._lock = None
        self._heads_mtx = threading.Lock()
        self._builds_mtx = threading.Lock()
        self._builds_queue = queue.Queue()
        self._builds_set = set()
        self._build_worker = self.JobWorker(self)
        self._build_worker.start()
        if not os.path.exists(self.BLOBDIR):
            os.makedirs(self.BLOBDIR)
        if not os.path.exists(self.BUILDS):
            os.makedirs(self.BUILDS)
        self.blobs = mbs.blobs.BlobStore(self.BLOBDIR)
        self.processes = ProcessArtifactMap(self.PROCESSES)
        if not os.path.exists(self.GITREPOS):
            os.makedirs(self.GITREPOS)
        if not os.path.exists(self.GITCACHE):
            os.makedirs(self.GITCACHE)
        if not os.path.exists(self.TARGETS):
            os.makedirs(self.TARGETS)
        if not os.path.exists(os.path.join(self.GITCACHE, 'config')):
            try:
                p = subprocess.Popen(('git', 'init', '--bare'),
                                     cwd=self.GITCACHE,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout, stderr = p.communicate()
                if p.returncode != 0:
                    raise MinionError("could not initialize git cache:\n" + stdout)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    raise MinionError('git binary not found (is it installed?)')
                raise e
        self.skipped_log = self.blobs.cat(b'minion skipped execution of this process\n')
        self.lock_workdir()

    @property
    def LOCK(self):
        return os.path.join(self.workdir, 'LOCK')

    @property
    def BLOBDIR(self):
        return os.path.join(self.workdir, 'blobs')

    @property
    def GITREPOS(self):
        return os.path.join(self.workdir, 'gitrepos')

    @property
    def GITCACHE(self):
        return os.path.join(self.workdir, 'gitcache')

    @property
    def HEADS(self):
        return os.path.join(self.workdir, 'HEADS')

    @property
    def BUILD(self):
        return os.path.join(self.workdir, 'build')

    @property
    def BUILDS(self):
        return os.path.join(self.workdir, 'builds')

    @property
    def PROCESSES(self):
        return os.path.join(self.workdir, 'processes')

    @property
    def MINIONFILE(self):
        return os.path.join(self.BUILD, 'Minionfile')

    @property
    def TARGETS(self):
        return os.path.join(self.workdir, 'targets')

    def TARGET(self, name):
        if not self.IS_TARGET(name):
            raise MinionError('invalid name for a target')
        return os.path.join(self.TARGETS, name)

    def IS_TARGET(self, name):
        TARGET_RE = '^[a-zA-Z0-9_][-a-zA-Z0-9_.]*$'
        return re.match(TARGET_RE, name) is not None

    def TARGET_AUTO(self, name):
        return os.path.join(self.TARGET(name), 'AUTO')

    def TARGET_HEADS(self, name):
        return os.path.join(self.TARGET(name), 'HEADS')

    class JobWorker(threading.Thread):

        def __init__(self, daemon):
            threading.Thread.__init__(self)
            self.minion_daemon = daemon
            self.daemon = True

        def run(self):
            while True:
                md = self.minion_daemon
                output, jc = md._builds_queue.get()
                jc.run()
                for report in jc.reports:
                    report = dict(report._asdict())
                    report['name'] = str(report['name'])
                    output['reports'].append(report)
                report = json.dumps(output)
                rblob = md.blobs.cat(report.encode('utf8'))
                report_name = output['name']
                md.blobs.copy(rblob, os.path.join(md.BUILDS, report_name))
                with md._builds_mtx:
                    md._builds_set.remove(report_name)

    def lock_workdir(self):
        self._lock = open(self.LOCK, 'w')
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except IOError as e:
            if e.errno != errno.EAGAIN:
                raise e
            raise MinionError("working directory already in use by another minion instance")

    def context(self):
        # XXX read from file
        return {'project': 'consus'}

    def api_target_new(self, name):
        with self._heads_mtx:
            path = self.TARGET(name)
            if os.path.exists(path):
                raise MinionError('target %r already exists' % name)
            if not os.path.exists(self.HEADS):
                raise MinionError('heads missing; sync and retry')
            os.makedirs(path)
            shutil.copyfile(self.HEADS, self.TARGET_AUTO(name))
            shutil.copyfile(self.HEADS, self.TARGET_HEADS(name))

    def api_target_del(self, name):
        with self._heads_mtx:
            path = self.TARGET(name)
            if not os.path.exists(path):
                raise MinionError("target %r doesn't exist" % name)
            shutil.rmtree(path)

    def api_targets(self):
        with self._heads_mtx:
            return self.list_targets()

    def api_target(self, name):
        if not os.path.exists(self.TARGET(name)):
            return None
        with self._heads_mtx:
            HEADS = self.heads_read(self.HEADS)
            autos = self.heads_read(self.TARGET_AUTO(name))
            heads = self.heads_read(self.TARGET_HEADS(name))
        ALL = set(HEADS.keys()) | set(autos.keys()) | set(heads.keys())
        ret = {}
        ret['sync-status'] = 'up-to-date'
        ret['heads'] = {}
        merged = {}
        merged.update(HEADS)
        merged.update(autos)
        merged.update(heads)
        for head in ALL:
            if head not in HEADS:
                ret['sync-status'] = 'out-of-sync'
            ret['heads'][head] = merged[head]
            # XXX say something about pinned refspecs here
        return ret

    def api_targets_sync(self, select=()):
        select = tuple(map(SourceIdentifier, select))
        removed = []
        updated = []
        with self._heads_mtx:
            sources = [src for src in self.parse() if issource(src)]
            normals = [src.name.normal for src in sources]
            if not select:
                select = tuple([src.name for src in sources])
            if not set(select).issubset(set([src.name for src in sources])):
                raise MinionError('invalid source(s) selected')
            if os.path.exists(self.HEADS):
                old_ptrs = self.heads_read(self.HEADS)
            else:
                old_ptrs = {}
            new_ptrs = old_ptrs.copy()
            missing = set(normals) - set(new_ptrs.keys())
            for src in sources:
                if src.name not in select and src.name.normal not in missing:
                    continue
                updated.append(src.name.normal)
                if isinstance(src, mbs.parser.FetchSource):
                    ptr = self.source_fetch(src)
                elif isinstance(src, mbs.parser.GitSource):
                    ptr = self.source_git(src)
                else:
                    assert False
                assert ptr is not None
                refspec, name = ptr.split(' ', 1)
                new_ptrs[src.name.normal] = {'refspec': refspec, 'name': name}
                ptr = None
            for head in set(new_ptrs.keys()) - set(normals):
                del new_ptrs[head]
                removed.append(head)
            self.heads_write(self.HEADS, new_ptrs, normals)
            for target in self.list_targets():
                self.sync_target(target, new_ptrs, normals)
        # XXX return something better here that describes everything that the
        # updated did
        return updated

    def api_target_set_refspec(self, target, head, refspec):
        with self._heads_mtx:
            path = self.TARGET(target)
            if not os.path.exists(path):
                raise MinionError("target %r doesn't exist" % target)
            sources = [src for src in self.parse()
                       if issource(src) and src.name == SourceIdentifier(head)]
            if len(sources) != 1:
                raise MinionError("head %r doesn't exist" % head)
            source = sources[0]
            if not isgit(source):
                raise MinionError('cannot set refspec for non-git source %r' % head)
            ptrs = self.heads_read(self.TARGET_HEADS(target))
            ptr = self.source_git(source, refspec)
            refspec, name = ptr.split(' ', 1)
            ptrs[head] = {'refspec': refspec, 'name': name}
            normals = [src.name.normal for src in self.parse() if issource(src)]
            self.heads_write(self.TARGET_HEADS(target), ptrs, normals)

    def api_build(self, target, processes=(), name=None, retry_failures=False):
        chosen_procs = None
        if processes:
            chosen_procs = self.parse_subset(processes)
        report_name = name or datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
        report_name = target + ':' + report_name
        path = self.TARGET(target)
        if not os.path.exists(path):
            raise MinionError("target %r doesn't exist" % target)
        with self._heads_mtx:
            mblob = self.blobs.add(self.MINIONFILE)
            sblob = self.blobs.add(os.path.join(path, 'HEADS'))
        minionfile = self.blobs.path(mblob)
        sources = self.blobs.path(sblob)
        loaded = self.heads_read(sources)
        loaded = dict([(k, '%s %s' % (v['refspec'], v['name']))
                       for k, v in loaded.items()])
        jc = JobController(self, loaded, report_name)
        jc.retry_failures = retry_failures
        for proc in self.parse(minionfile):
            if not isprocess(proc):
                continue
            if not processes or proc.name in chosen_procs:
                jc.add(proc)
        output = {}
        output['name'] = report_name
        output['minionfile'] = mblob
        output['sources'] = sblob
        output['reports'] = []
        with self._builds_mtx:
            path = os.path.join(self.BUILDS, report_name)
            if os.path.exists(path) or report_name in self._builds_set:
                raise MinionError('build %r already exists' % report_name)
            self._builds_set.add(report_name)
            self._builds_queue.put((output, jc))
        return {'status': 'success'}

    def api_builds(self):
        builds = []
        for x in sorted(os.listdir(self.BUILDS)):
            target, name = x.split(':', 1)
            date = datetime.datetime.utcfromtimestamp(os.stat(os.path.join(self.BUILDS, x)).st_mtime)
            builds.append({'id': x, 'target': target, 'name': name,
                           'date': date.strftime('%Y-%m-%dT%H:%M:%SZ')})
        return builds

    def api_build_status(self, build):
        path = os.path.join(self.BUILDS, build)
        if not os.path.exists(path):
            return None
        build = json.load(open(path))
        minionfile = self.parse(self.blobs.path(build['minionfile']))
        # check for older versions of the build format
        if 'reports' in build and 'processes' not in build:
            build['processes'] = build['reports']
            del build['reports']
        for process in build['processes']:
            proc = [p for p in minionfile
                    if isprocess(p) and p.name == ProcessIdentifier(process['name'])]
            if len(proc) != 1:
                raise MinionError('build %s is corrupt' % build)
            proc = proc[0]
            del process['idx']
            process['deps'] = {}
            if process['inputs'] == '-':
                process['type'] = 'skipped'
            else:
                inputs = self.inputs_read(process['inputs'])
                if inputs['process'] != process['name']:
                    raise MinionError('build %s is corrupt' % build)
                process['type'] = inputs['type']
                for n, r in inputs['deps']:
                    process['deps'][n] = r
                if process['type'] == 'docker':
                    process['docker-image'] = inputs['image']
                else:
                    assert False
            del process['inputs']
            process['artifacts'] = []
            if process['outputs'] == '-':
                process['log'] = self.skipped_log
            else:
                outputs = self.outputs_read(proc, process['outputs'])
                process['log'] = outputs['log']
                for a, (r, n) in outputs['artifacts'].items():
                    process['artifacts'].append({
                        'id': str(a),
                        'name': n,
                        'refspec': r
                    })
            del process['outputs']
        return build

    def api_log_path(self, logid):
        path = self.blobs.path(logid)
        if not os.path.exists(path):
            return None
        return path

    def parse(self, path=None):
        return mbs.parser.parse(path or self.MINIONFILE)

    def parse_subset(self, processes, path=None):
        parsed = self.parse(path)
        normalnames = set()
        processnames2processes = {}
        artifacts2processnames = {}
        for proc in parsed:
            if not isprocess(proc):
                continue
            normalnames.add(str(proc.name))
            processnames2processes[proc.name] = proc
            for a in proc.artifacts:
                artifacts2processnames[a] = proc.name
        q = collections.deque()
        required = set()
        for proc in processes:
            found = False
            for cand in normalnames:
                if fnmatch.fnmatch(cand, proc):
                    found = True
                    p = ProcessIdentifier(cand)
                    if p not in required:
                        required.add(p)
                        q.append(p)
            if not found:
                raise MinionError('unknown process or pattern %r' % proc)
        while len(q) > 0:
            proc = q.pop()
            proc = processnames2processes[proc]
            for d in proc.dependencies:
                if d in artifacts2processnames:
                    p = artifacts2processnames[d]
                    if p not in required:
                        q.append(p)
                        required.add(p)
        return required

    def atomic_write(self, path, content):
        f = tempfile.NamedTemporaryFile(prefix='minion-', dir=self.workdir)
        f.write(content)
        f.flush()
        os.rename(f.name, path)
        os.link(path, f.name)
        f.close()

    def source_fetch(self, src):
        assert isinstance(src, mbs.parser.FetchSource)
        if src.sha256 and self.blobs.has(src.sha256):
            return src.sha256 + ' ' + str(src.name)
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp(prefix='minion-')
            path = os.path.join(tmpdir, 'fetched')
            try:
                urllib.request.urlretrieve(src.url, path)
            except urllib.error.HTTPError as e:
                raise MinionError('could not retrieve %s: %s' % (src.name, e))
            sha256 = self.blobs.add(path)
            if src.sha256 is not None and sha256 != src.sha256:
                raise MinionError('checksum mismatch on source %s' % src.name)
            return sha256 + ' ' + str(src.name)
        finally:
            if tmpdir is not None and os.path.exists(tmpdir):
                shutil.rmtree(tmpdir)

    def source_git(self, src, refspec=None):
        assert isinstance(src, mbs.parser.GitSource)
        refspec = refspec or src.branch or 'master'
        repo = os.path.join(self.GITREPOS, src.name.normal)
        if os.path.exists(repo) and os.path.isdir(repo):
            shutil.rmtree(repo)
        try:
            env = {'GIT_DIR': self.GITCACHE}
            if 'SSH_AUTH_SOCK' in os.environ:
                env['SSH_AUTH_SOCK'] = os.environ['SSH_AUTH_SOCK']
            if 'SSH_AGENT_PID' in os.environ:
                env['SSH_AGENT_PID'] = os.environ['SSH_AGENT_PID']
            run_no_fail(('git', 'remote', 'rm', src.name.normal), env=env)
            run('git-remote-add', ('git', 'remote', 'add', src.name.normal, src.url), env=env)
            run('git-fetch', ('git', 'fetch', src.name.normal), env=env)
            run('git-clone', ('git', 'clone', '--mirror', '--shared', '--reference',
                              self.GITCACHE, src.url, repo), env=env)
            env = {'GIT_DIR': repo}
            rev = run('git-rev-list', ('git', 'rev-list', '-n', '1', refspec), env=env)
            rev = rev.decode('utf8')
            return rev.strip() + ' ' + refspec
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise MinionError('git binary not found (is it installed?)')
            raise e

    def heads_read(self, path):
        if not os.path.exists(path):
            raise MinionError("cannot read heads from %s because it doesn't exist" % path)
        f = open(path)
        srcs = {}
        for x in f:
            a, b = x.strip().split(': ')
            r, n = b.split(' ', 1)
            srcs[a] = {'refspec': r, 'name': n}
        return srcs

    def heads_write(self, path, ptrs, order):
        def key(x):
            return order.index(x[0])
        content = ''
        for norm, v in sorted(ptrs.items(), key=key):
            content += '%s: %s %s\n' % (norm, v['refspec'], v['name'])
        self.atomic_write(path, content.encode('utf8'))

    def list_targets(self):
        targets = []
        for x in os.listdir(self.TARGETS):
            if self.IS_TARGET(x):
                targets.append(x)
        return sorted(targets)

    def sync_target(self, target, ptrs, order):
        autos = self.heads_read(self.TARGET_AUTO(target))
        heads = self.heads_read(self.TARGET_HEADS(target))
        for k in set(autos.keys()) - set(ptrs.keys()):
            del autos[k]
        for k in set(ptrs.keys()) - set(autos.keys()):
            autos[k] = ptrs[k]
        for k in set(heads.keys()) - set(ptrs.keys()):
            del heads[k]
        for k in set(ptrs.keys()) - set(heads.keys()):
            heads[k] = ptrs[k]
        def ptrcmp(a, b):
            return a['refspec'] == b['refspec'] and a['name'] == b['name']
        for src in set(ptrs.keys()):
            assert src in autos
            assert src in heads
            if ptrcmp(autos[src], heads[src]) and not ptrcmp(autos[src], ptrs[src]):
                heads[src] = ptrs[src]
            autos[src] = ptrs[src]
        self.heads_write(self.TARGET_AUTO(target), autos, order)
        self.heads_write(self.TARGET_HEADS(target), heads, order)

    def inputs_read(self, ref):
        contents = self.blobs.read(ref).decode('utf8')
        if contents.startswith('Dockerfile'):
            process = re.search('^Process: (.*)$', contents, re.MULTILINE)
            image = re.search('^Image: ([0-9a-fA-F]+)$', contents, re.MULTILINE)
            if process is None or image is None:
                raise MinionError('input %s is corrupt' % ref)
            deps = re.findall('^Dependency (.*): ([0-9a-fA-F]+)$', contents, re.MULTILINE)
            return {'type': 'docker',
                    'process': process.group(1),
                    'image': image.group(1),
                    'deps': deps}
        else:
            raise MinionError('Unknown input format')

    def outputs_read(self, proc, ref):
        contents = self.blobs.dump(ref).decode('utf8')
        status = re.search('^Status: (\w+)$', contents, re.MULTILINE)
        if status is None:
            raise MinionError('output %s is corrupt' % ref)
        status = status.group(1)
        log = re.search('^Log: ([0-9A-Fa-f]+)$', contents, re.MULTILINE)
        if log is None:
            raise MinionError('output %s is corrupt' % ref)
        log = log.group(1)
        artifacts = {}
        for d, s, p in re.findall('^Artifact (\S+): ([0-9A-Fa-f]+) (\S+)$', contents, re.MULTILINE):
            envvar = identifier_to_envvar(d, prefix='artifact')
            for a in proc.artifacts:
                if envvar == a.var:
                    artifacts[a] = (s, p)
        return {'status': status,
                'log': log,
                'artifacts': artifacts}

#################################### Web App ###################################

app = flask.Flask(__name__)

@app.route('/api/target/new', methods=('POST',))
def api_target_new():
    try:
        if 'target' not in request.values:
            assert False # XXX bad request
        app.daemon.api_target_new(request.values['target'])
        return flask.jsonify(success=True)
    except:
        raise # XXX

@app.route('/api/target/del', methods=('POST',))
def api_target_del():
    try:
        if 'target' not in request.values:
            assert False # XXX bad request
        app.daemon.api_target_del(request.values['target'])
        return flask.jsonify(success=True)
    except:
        raise # XXX

@app.route('/api/targets.json')
def api_targets():
    try:
        targets = app.daemon.api_targets()
        return flask.jsonify(targets=targets)
    except:
        raise # XXX

@app.route('/api/targets/sync', methods=('POST',))
def api_targets_sync():
    try:
        select = ()
        if 'heads' in request.values:
            select = request.values['heads'].split(',')
        heads = app.daemon.api_targets_sync(select)
        return flask.jsonify(heads=heads)
    except:
        raise # XXX

@app.route('/api/target/<target>/set-refspec', methods=('POST',))
def api_target_set_refspec(target):
    try:
        if 'head' not in request.values:
            assert False # XXX bad request
        if 'refspec' not in request.values:
            assert False # XXX bad request
        app.daemon.api_target_set_refspec(target, request.values['head'], request.values['refspec'])
        return flask.jsonify(success=True)
    except:
        raise # XXX

@app.route('/api/target/<target>.json')
def api_target(target):
    try:
        target = app.daemon.api_target(target)
        if not target:
            assert False # XXX 404
        return flask.jsonify(**target)
    except:
        raise # XXX

@app.route('/api/target/<target>/build', methods=('POST',))
def api_build(target):
    try:
        processes = ()
        if 'processes' in request.values:
            processes = request.values['processes'].split(',')
        name = request.values.get('name', None)
        retry_failures = 'retry' in request.values
        app.daemon.api_build(target, processes, name, retry_failures)
        return flask.jsonify(success=True)
    except:
        raise # XXX

@app.route('/api/builds.json')
def api_builds():
    try:
        builds = app.daemon.api_builds()
        return flask.jsonify(builds=builds)
    except:
        raise # XXX

@app.route('/api/build/<build>.json')
def api_build_status(build):
    try:
        build = app.daemon.api_build_status(build)
        if not build:
            assert False # XXX 404
        return flask.jsonify(**build)
    except:
        raise # XXX

@app.route('/api/log/<logid>')
def api_log(logid):
    try:
        path = app.daemon.api_log_path(logid)
        if not path:
            assert False # XXX 404
        return flask.send_file(path, mimetype='text/plain')
    except:
        raise # XXX

@app.route('/')
def index():
    return render_template('overview.html', **app.daemon.context())

@app.route('/builds')
def builds():
    builds = app.daemon.api_builds()
    builds.sort(key=lambda x: x['date'], reverse=True)
    return render_template('builds.html', builds={'builds': builds}, **app.daemon.context())

@app.route('/build/<build>')
def build(build):
    build = app.daemon.api_build_status(build)
    if not build:
        assert False # XXX 404
    return render_template('build.html', build={'build': build}, **app.daemon.context())

@app.route('/download/<refspec>/<path:path>')
def download(refspec, path):
    blob = app.daemon.blobs.path(refspec)
    if not os.path.exists(blob):
        assert False
    return flask.send_file(blob, as_attachment=True,
            attachment_filename=path)

def main_daemon(argv):
    app.debug = True
    app.daemon = MinionDaemon(os.path.abspath('.'))#XXX
    app.run('0.0.0.0', 31337, threaded=True, use_reloader=False,
            static_files={'/': os.path.join(os.path.dirname(__file__), 'files')})
