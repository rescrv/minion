# Copyright (c) 2014-2015, Robert Escriva
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

import minion.blobs
import minion.cmd
import minion.parser
import minion.logger as logger

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
    return isinstance(x, minion.parser.FetchSource) or isinstance(x, minion.parser.GitSource)

def isgit(x):
    return isinstance(x, minion.parser.GitSource)

def isprocess(x):
    return isdockerfileprocess(x)

def isdockerfileprocess(x):
    return isinstance(x, minion.parser.DockerfileProcess)

def utcnow():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

def run(name, args, env=None, cwd=None):
    p = subprocess.Popen(args, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        raise MinionException(("%s failed:\n%s" % (name, stdout.decode('utf8', 'ignore'))).strip())
    return stdout

def run_no_fail(args, env=None):
    p = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = p.communicate()

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
            raise MinionException("git binary not found (is it installed?)")
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
                raise MinionException("no support for process %s" % proc.name)

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
                logger.info('starting')
                return True
            else:
                logger.info('skipped because of prior failure')
                return False

    def is_cached(self, stub):
        iid = self.minion.blobs.cat(stub)
        oid = self.minion.processes.lookup(iid)
        return oid is not None

    def get_cached(self, proc, stub):
        iid = self.minion.blobs.cat(stub)
        oid = self.minion.processes.lookup(iid)
        return self.minion.read_output(proc, oid)

    def finish_cached(self, proc, stub, released=False):
        iid = self.minion.blobs.cat(stub)
        oid = self.minion.processes.lookup(iid)
        assert oid is not None
        success, log, artifacts = self.minion.read_output(proc, oid)
        with self.mtx:
            if success:
                logger.info('cached: success')
            else:
                logger.info('cached: failure')
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
            if success:
                logger.info('finished: success')
            else:
                logger.info('finished: failure')
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
                    raise MinionException("unknown source %s: try running auto-sources" % str(d))
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
            logger.meta.prefix = '[build %s/%s] ' % (self.controller.name, self.proc.name)
            if not self.controller.wait_for(self.proc):
                return
            sources, artifacts = self.controller.get_inputs()
            stub = self.stub(sources, artifacts, '-')
            if self.controller.is_cached(stub):
                logger.debug('finishing with released copy')
                self.controller.finish_cached(self.proc, stub, released=True)
                return
            image = self.build_image(self.proc.path)
            logger.debug('docker image is %r' % image)
            stub = self.stub(sources, artifacts, image)
            if self.controller.is_cached(stub):
                success, X, X = self.controller.get_cached(self.proc, stub)
                if success or not self.controller.retry_failures:
                    logger.debug('finishing with cached copy')
                    self.controller.finish_cached(self.proc, stub)
                    return
            success, log, artifacts =  self.run_image(sources, artifacts, stub, image)
            if success:
                self.controller.finish_success(self.proc, stub, log, artifacts)
            else:
                self.controller.finish_error(self.proc, stub, log)
        except Exception as e:
            logger.exception('docker worker failed')
        finally:
            self.controller.abort_if_not_finished(self.proc)

    def build_image(self, path):
        try:
            img = run('docker build of %s' % path, ('docker', 'build', path),
                      cwd=self.controller.minion.BUILD)
            img = img.decode('utf8')
            m = re.search('Successfully built ([0-9A-Fa-f]+)', img)
            if not m:
                raise MinionException("docker build failed, but docker exited 0")
            return m.group(1)
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise MinionException("could not run docker (is it installed?)")
            raise e

    def run_image(self, sources, artifacts, stub, image):
        tmp = None
        try:
            tmp = tempfile.mkdtemp(prefix='minion-sources-', dir=self.controller.minion.workdir)
            logger.debug('running out of directory %r' % tmp)
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
                raise MinionException("could not run docker (is it installed?)")
            raise e
        finally:
            if tmp is not None:
                shutil.rmtree(tmp)

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
        logger.debug('removed process mapping %s... -> %s...' % (inputs_id[:8], x[:8]))

    def _path(self, sha256):
        assert len(sha256) == 64
        a, b, c = sha256[0:2], sha256[2:4], sha256[4:]
        return os.path.join(self.base, a, b, c)

class MinionException(Exception): pass

class MinionArgumentParserError(MinionException): pass

class MinionThrowingArgumentParser(argparse.ArgumentParser):

    # XXX avoid help and usage
    def error(self, message):
        raise MinionArgumentParserError(message)

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
        self._threads_mtx = threading.Lock()
        self._threads = set()
        if not os.path.exists(self.BLOBDIR):
            os.makedirs(self.BLOBDIR)
        if not os.path.exists(self.BUILDS):
            os.makedirs(self.BUILDS)
        self.blobs = minion.blobs.BlobStore(self.BLOBDIR)
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
                    raise MinionException("could not initialize git cache:\n" + stdout)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    raise MinionException('git binary not found (is it installed?)')
                raise e

    @property
    def LOCK(self):
        return os.path.join(self.workdir, 'LOCK')

    @property
    def LOGFILE(self):
        return os.path.join(self.workdir, 'minion.log')

    @property
    def SOCKET(self):
        return os.path.join(self.workdir, 'minion.sock')

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
            raise MinionException('invalid name for a target')
        return os.path.join(self.TARGETS, name)

    def IS_TARGET(self, name):
        TARGET_RE = '^[a-zA-Z0-9_][-a-zA-Z0-9_.]*$'
        return re.match(TARGET_RE, name) is not None

    class JobWorker(threading.Thread):

        def __init__(self, daemon):
            threading.Thread.__init__(self)
            self.minion_daemon = daemon
            self.daemon = True

        def run(self):
            while True:
                md = self.minion_daemon
                output, jc = md._builds_queue.get()
                logger.info('[build %s] starting' % output['name'])
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
                logger.info('[build %s] finished' % output['name'])

    class Acceptor(threading.Thread):

        def __init__(self, daemon, sock):
            threading.Thread.__init__(self)
            self.minion_daemon = daemon
            self.sock = sock

        def run(self):
            ident = self.minion_daemon.add_thread()
            logger.meta.prefix = '[%s] ' % ident
            info = None
            try:
                creds = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
                info = 'pid=%d, uid=%d, gid=%d' % struct.unpack('3i', creds)
                logger.info('accepting connection from %s' % (info,))
                buf = b''
                while True:
                    data = self.sock.recv(4096)
                    if not data:
                        break
                    buf += data
                    if b'\n' not in buf:
                        continue
                    cmds = buf.split(b'\n')
                    buf = cmds[-1]
                    cmds = cmds[:-1]
                    for cmd in cmds:
                        cmd = cmd.decode('ascii')
                        logger.debug('received %r' % (cmd,))
                        output = self.minion_daemon.dispatch(self.sock, cmd)
                        self.sock.sendall(json.dumps(output).encode('utf8'))
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except BrokenPipeError as e:
                pass
            except Exception as e:
                logger.exception('error processing request')
            finally:
                self.minion_daemon.rm_thread(ident)
                logger.info('finished')

    def run(self):
        self.lock_workdir()
        self.configure_logging()
        sock = self.create_socket()
        while True:
            conn, addr = sock.accept()
            t = MinionDaemon.Acceptor(self, conn)
            t.daemon = True
            t.start()

    def lock_workdir(self):
        self._lock = open(self.LOCK, 'w')
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except IOError as e:
            if e.errno != errno.EAGAIN:
                raise e
            raise MinionException("working directory already in use by another minion instance")

    def configure_logging(self):
        fmt = '%(asctime)s %(levelname)-8s %(message)s'
        dtf = '%Y-%m-%dT%H:%M:%S'
        logging.basicConfig(filename=self.LOGFILE, format=fmt, datefmt=dtf, level=logging.DEBUG)
        logger.info('starting new minion-daemon: pid=%d' % os.getpid())

    def create_socket(self):
        logger.info("creating socket at %r" % self.SOCKET)
        if os.path.exists(self.SOCKET):
            logger.debug('socket already exists; erasing it')
            os.unlink(self.SOCKET)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.SOCKET)
        sock.listen(8)
        return sock

    def add_thread(self):
        while True:
            ident = str(binascii.hexlify(os.urandom(4)), 'ascii')
            with self._threads_mtx:
                if ident in self._threads:
                    logger.debug('generated duplicate identifier %s' % ident)
                    continue
                self._threads.add(ident)
                logger.debug('generated identifier %s' % ident)
            return ident

    def rm_thread(self, ident):
        with self._threads_mtx:
            if ident in self._threads:
                self._threads.remove(ident)
                logger.debug('retired identifier %s' % ident)

    def parse(self, path=None):
        return minion.parser.parse(path or self.MINIONFILE)

    def parsed_sources(self, sources, path=None):
        parsed = [src for src in self.parse(path) if issource(src)]
        sources = [SourceIdentifier(s) for s in sources]
        if not sources:
            logger.debug('no sources provided, using all sources')
            sources = parsed
        else:
            by_name = dict([(s.name, s) for s in parsed])
            for idx, src in enumerate(sources):
                if src not in by_name:
                    raise MinionException("unknown source %r" % src.normal)
                sources[idx] = by_name[src]
        return parsed, sources

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
                raise MinionException('unknown process or pattern %r' % proc)
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

    def read_output(self, proc, oid):
        contents = self.blobs.dump(oid).decode('utf8')
        status = re.search('^Status: (\w+)$', contents, re.MULTILINE)
        assert status is not None
        status = status.group(1)
        log = re.search('^Log: ([0-9A-Fa-f]+)$', contents, re.MULTILINE)
        assert log is not None
        log = log.group(1)
        if log == '0' * 64:
            log = 'manually imported\n'
        else:
            log = self.blobs.dump(log)
        artifacts = {}
        for d, s, p in re.findall('^Artifact (\S+): ([0-9A-Fa-f]+) (\S+)$', contents, re.MULTILINE):
            envvar = identifier_to_envvar(d, prefix='artifact')
            for a in proc.artifacts:
                if envvar == a.var:
                    artifacts[a] = (s, p)
        return status == 'success', log, artifacts

    def atomic_write(self, path, content):
        f = tempfile.NamedTemporaryFile(prefix='minion-', dir=self.workdir)
        f.write(content)
        f.flush()
        os.rename(f.name, path)
        os.link(path, f.name)
        f.close()

    def dispatch(self, sock, cmd):
        cmd = shlex.split(cmd, posix=True)
        if not cmd:
            logger.error('[%s] submitted empty command')
            return
        assert len(cmd) > 0
        try:
            if cmd[0] == 'update-heads':
                return self.dispatch_update_heads(sock, cmd[1:])
            elif cmd[0] == 'new-target':
                return self.dispatch_new_target(sock, cmd[1:])
            elif cmd[0] == 'del-target':
                return self.dispatch_del_target(sock, cmd[1:])
            elif cmd[0] == 'set-refspec':
                return self.dispatch_set_refspec(sock, cmd[1:])
            elif cmd[0] == 'build':
                return self.dispatch_build(sock, cmd[1:])
            elif cmd[0] == 'status':
                return self.dispatch_status(sock, cmd[1:])
            elif cmd[0] == 'add-blob':
                return self.dispatch_add_blob(sock, cmd[1:])
            else:
                logger.error('submitted unknown command %r' % (cmd[0],))
                return {'status': 'error', 'error': 'unknown command %r' % (cmd[0],)}
        except MinionException as e:
            logger.error('%s failed: %s' % (cmd[0], e))
            return {'status': 'exception', 'error': str(e)}
        except Exception as e:
            logger.exception('%s failed' % (cmd[0],))
            return {'status': 'exception', 'error': str(e)}

    def sync_target(self, parsed, sources, target, HEADS):
        path = self.TARGET(target)
        auto = self.sources_load(os.path.join(path, 'AUTO'))
        heads = self.sources_load(os.path.join(path, 'HEADS'))
        for k in set(auto.keys()):
            if k not in HEADS:
                del auto[k]
        for k in set(heads.keys()):
            if k not in HEADS:
                del heads[k]
        for src in sources:
            name = src.name.normal
            assert name in HEADS
            if name not in heads or \
               name not in auto or \
               (auto[name] == heads[name] and auto[name] != HEADS[name]):
                heads[name] = HEADS[name]
                logger.info('updating head %r in target %r' % (name, target))
            auto[name] = HEADS[name]
        parsed_names = [p.name.normal for p in parsed]
        self.sources_save(os.path.join(path, 'AUTO'), auto, parsed_names)
        self.sources_save(os.path.join(path, 'HEADS'), heads, parsed_names)

    def dispatch_update_heads(self, sock, cmd):
        parser = minion.cmd.update_heads(MinionThrowingArgumentParser())
        args = parser.parse_args(cmd)
        with self._heads_mtx:
            parsed, sources = self.parsed_sources(args.sources)
            ptrs = {}
            for src in sources:
                ptr = None
                if isinstance(src, minion.parser.FetchSource):
                    ptr = self.get_source_fetch(src)
                elif isinstance(src, minion.parser.GitSource):
                    ptr = self.get_source_git(src)
                else:
                    assert False
                assert ptr is not None
                logger.debug('head of %s is %s' % (src.name, ptr))
                ptrs[src.name.normal] = ptr
            if os.path.exists(self.HEADS):
                logger.debug('HEADS file exists; parsing it')
                old_ptrs = self.sources_load(self.HEADS)
            else:
                logger.debug('HEADS file does not exist; will create it')
                old_ptrs = {}
            new_ptrs = old_ptrs.copy()
            new_ptrs.update(ptrs)
            A = set(new_ptrs.keys())
            B = set([p.name.normal for p in parsed])
            parsed_names = [p.name.normal for p in parsed]
            if A != B:
                missing = B - A
                missing = sorted(missing, key=parsed_names.index)
                logger.warning('missing head for %s' % (', '.join(missing),))
            self.sources_save(self.HEADS, new_ptrs, parsed_names)
            for target in self.list_targets():
                self.sync_target(parsed, sources, target, new_ptrs)
        return {'status': 'success'}

    def list_targets(self):
        targets = []
        for x in os.listdir(self.TARGETS):
            if self.IS_TARGET(x):
                targets.append(x)
        return sorted(targets)

    def dispatch_new_target(self, sock, cmd):
        parser = minion.cmd.new_target(MinionThrowingArgumentParser())
        args = parser.parse_args(cmd)
        with self._heads_mtx:
            path = self.TARGET(args.target)
            if os.path.exists(path):
                raise MinionException('target %r already exists' % args.target)
            if not os.path.exists(self.HEADS):
                raise MinionException('heads missing; run update-heads and retry')
            os.makedirs(path)
            logger.info('creating target %r' % (args.target,))
            shutil.copyfile(self.HEADS, os.path.join(path, 'AUTO'))
            shutil.copyfile(self.HEADS, os.path.join(path, 'HEADS'))
        return {'status': 'success'}

    def dispatch_del_target(self, sock, cmd):
        parser = minion.cmd.del_target(MinionThrowingArgumentParser())
        args = parser.parse_args(cmd)
        with self._heads_mtx:
            path = self.TARGET(args.target)
            if not os.path.exists(path):
                raise MinionException("target %r doesn't exist" % args.target)
            logger.info('deleting target %r' % (args.target,))
            shutil.rmtree(path)
        return {'status': 'success'}

    def dispatch_set_refspec(self, sock, cmd):
        parser = minion.cmd.set_refspec(MinionThrowingArgumentParser())
        args = parser.parse_args(cmd)
        with self._heads_mtx:
            path = self.TARGET(args.target)
            if not os.path.exists(path):
                raise MinionException("target %r doesn't exist" % args.target)
            parsed, sources = self.parsed_sources([args.source])
            assert len(sources) == 1
            source = sources[0]
            path = self.TARGET(args.target)
            heads = self.sources_load(os.path.join(path, 'HEADS'))
            if not isgit(source):
                raise MinionException('cannot set refspec for non-git source %s' % source)
            heads[source.name.normal] = self.get_source_git(source, args.refspec)
            logger.info('updating head %r in target %r to %r' %
                         (source.name.normal, args.target, args.refspec))
            parsed_names = [p.name.normal for p in parsed]
            self.sources_save(os.path.join(path, 'HEADS'), heads, parsed_names)
        return {'status': 'success'}

    def dispatch_build(self, sock, cmd):
        parser = minion.cmd.build(MinionThrowingArgumentParser())
        args = parser.parse_args(cmd)
        chosen_procs = None
        if args.processes:
            args.processes = tuple(args.processes.split(','))
            chosen_procs = self.parse_subset(args.processes)
        report_name = args.name or datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
        report_name = args.target + ':' + report_name
        logger.info('running build process for %s; results will be saved to %s' % (args.target, report_name))
        path = self.TARGET(args.target)
        if not os.path.exists(path):
            raise MinionException("target %r doesn't exist" % args.target)
        with self._heads_mtx:
            mblob = self.blobs.add(self.MINIONFILE)
            sblob = self.blobs.add(os.path.join(path, 'HEADS'))
        minionfile = self.blobs.path(mblob)
        logger.debug('using minionfile %s' % minionfile)
        sources = self.blobs.path(sblob)
        logger.debug('using sources %s' % sources)
        jc = JobController(self, self.sources_load(sources), report_name)
        jc.retry_failures = args.retry_failures
        for proc in self.parse(minionfile):
            if not isprocess(proc):
                continue
            if not args.processes or proc.name in chosen_procs:
                logger.debug('adding %s' % (proc,))
                jc.add(proc)
        output = {}
        output['name'] = report_name
        output['minionfile'] = mblob
        output['sources'] = sblob
        output['reports'] = []
        with self._builds_mtx:
            path = os.path.join(self.BUILDS, report_name)
            if os.path.exists(path) or report_name in self._builds_set:
                raise MinionException('build %r already exists' % report_name)
            self._builds_set.add(report_name)
            self._builds_queue.put((output, jc))
        return {'status': 'success'}

    def get_build(self, target, name=None):
        with self._builds_mtx:
            builds = os.listdir(self.BUILDS)
            def keep(x):
                if name is None:
                    return x.startswith(target + ':')
                else:
                    return x == target + ':' + name
            builds = [b for b in builds if keep(b)]
            def key(x):
                st = os.stat(os.path.join(self.BUILDS, x))
                return st.st_mtime
            builds = sorted(builds, key=key, reverse=True)
            if builds:
                return builds[0]
            else:
                return None

    def dispatch_status(self, sock, cmd):
        parser = minion.cmd.status(MinionThrowingArgumentParser())
        args = parser.parse_args(cmd)
        if args.name is not None:
            display_name = '%s:%s' % (args.target, args.name)
        else:
            display_name = '%s' % args.target
        logger.info('checking build status of %s' % display_name)
        build = self.get_build(args.target, args.name)
        reporter = args.report.replace('-', '_')
        reporter = getattr(self, 'report_' + reporter, None)
        if reporter is None:
            return {'status': 'failure', 'output': 'no such reporter'}
        if build is None:
            return {'status': 'failure', 'output': 'no such build as %s' % display_name}
        logger.info('generating %s report of %s' % (args.report, display_name))
        build = open(os.path.join(self.BUILDS, build)).read()
        report = json.loads(build)
        return {'status': 'success', 'output': reporter(report)}

    def report_one_bit(self, report):
        success = True
        for x in report['reports']:
            if not x['success']:
                success = False
        if success:
            return 'success'
        else:
            return 'failure'

    def report_short(self, report):
        r = ''
        r += 'Minionfile: %s\n' % report['minionfile']
        r += 'Sources: %s\n' % report['sources']
        r += '\n'
        for idx, x in enumerate(report['reports']):
            if x['success']:
                r += x['name'] + ': success'
                if x['released']:
                    r += ' [released]'
                elif x['cached']:
                    r += ' [cached]'
                r += '\n'
            else:
                r += '%s: failure\n' % x['name']
        return r

    def report_long(self, report):
        r = ''
        r += 'Minionfile: %s\n' % report['minionfile']
        r += 'Sources: %s\n' % report['sources']
        r += '\n'
        parsed = self.parse(self.blobs.path(report['minionfile']))
        for idx, x in enumerate(report['reports']):
            if x['success']:
                r += x['name'] + ': success'
                if x['released']:
                    r += ' [released]'
                elif x['cached']:
                    r += ' [cached]'
                r += '\n'
            elif '-' in (x['inputs'], x['outputs']) and not x['cached']:
                r += '%s: aborted\n' % x['name']
            else:
                r += '%s: failure\n' % x['name']
                proc = None
                for p in parsed:
                    if str(p.name) == x['name']:
                        proc = p
                if proc is None:
                    raise MinionException('report corrupt')
                success, log, artifacts = self.read_output(proc, x['outputs'])
                r += log.decode('utf8')
                break
        return r

    def report_full(self, report):
        r = ''
        r += 'Minionfile: %s\n' % report['minionfile']
        r += 'Sources: %s\n' % report['sources']
        r += '\n'
        parsed = self.parse(self.blobs.path(report['minionfile']))
        for idx, x in enumerate(report['reports']):
            print_log = False
            if x['success']:
                r += x['name'] + ': success'
                if x['released']:
                    r += ' [released]'
                elif x['cached']:
                    r += ' [cached]'
                r += '\n'
                print_log = True
            elif '-' in (x['inputs'], x['outputs']) and not x['cached']:
                r += '%s: aborted\n' % x['name']
            else:
                r += '%s: failure\n' % x['name']
                print_log = True
            if print_log:
                proc = None
                for p in parsed:
                    if str(p.name) == x['name']:
                        proc = p
                if proc is None:
                    raise MinionException('report corrupt')
                success, log, artifacts = self.read_output(proc, x['outputs'])
                r += log.decode('utf8')
                r += '\n' + '=' * 80 + '\n\n'
        return r

    def report_failed(self, report):
        r = ''
        for idx, x in enumerate(report['reports']):
            if not x['success']:
                r += '%s\n' % x['name']
        return r

    def report_docker_images(self, report):
        r = ''
        for x in report['reports']:
            if x['inputs'] == '-':
                continue
            stub = self.blobs.read(x['inputs']).decode('utf8', 'ignore')
            match = re.search('^Image: (\w+)$', stub, re.MULTILINE)
            if match is None:
                continue
            r += match.group(1) + '\n'
        return r

    def dispatch_add_blob(self, sock, cmd):
        parser = minion.cmd.add_blob(MinionThrowingArgumentParser())
        args = parser.parse_args(cmd)
        for blob in args.blobs:
            sha256 = self.blobs.add(blob)
            logger.info('manually added %s as %s...' % (blob, sha256[:8]))
        return {'status': 'success'}

    def sources_load(self, path):
        if not os.path.exists(path):
            raise MinionException("cannot load sources from %s because it doesn't exist" % path)
        f = open(path)
        srcs = {}
        for x in f:
            a, b = x.strip().split(': ')
            srcs[a] = b
        return srcs

    def sources_save(self, path, x, order):
        x = x.copy()
        for k in list(x.keys()):
            if k not in order:
                del x[k]
        def key(x):
            return order.index(x[0])
        content = '\n'.join([x + ': ' + y for x, y in sorted(x.items(), key=key)])
        self.atomic_write(path, (content + '\n').encode('utf8'))

    def get_source_fetch(self, src):
        assert isinstance(src, minion.parser.FetchSource)
        logger.debug('getting %s' % (src,))
        if src.sha256 and self.blobs.has(src.sha256):
            logger.debug('%s already in cache' % (src.name,))
            return src.sha256 + ' ' + str(src.name)
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp(prefix='minion-')
            path = os.path.join(tmpdir, 'fetched')
            try:
                logger.debug('saving %s to %s' % (src.url, path))
                urllib.request.urlretrieve(src.url, path)
            except urllib.error.HTTPError as e:
                raise MinionException('could not retrieve %s: %s' % (src.name, e))
            sha256 = self.blobs.add(path)
            logger.debug('sha256(%s) = %s' % (src.name, sha256))
            if src.sha256 is not None and sha256 != src.sha256:
                raise MinionException('checksum mismatch on source %s' % src.name)
            return sha256 + ' ' + str(src.name)
        finally:
            if tmpdir is not None and os.path.exists(tmpdir):
                shutil.rmtree(tmpdir)

    def get_source_git(self, src, refspec=None):
        assert isinstance(src, minion.parser.GitSource)
        refspec = refspec or src.branch or 'master'
        logger.debug('getting %s with refspec %s' % (src, refspec))
        repo = os.path.join(self.GITREPOS, src.name.normal)
        if os.path.exists(repo) and os.path.isdir(repo):
            logger.debug('repository exists; erasing it before cloning')
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
                raise MinionException('git binary not found (is it installed?)')
            raise e

def main_daemon(argv):
    parser = argparse.ArgumentParser(prog='minion-daemon')
    parser.add_argument('--workdir', default=os.environ.get('MINION_WORKDIR', '.'),
                        help='minion working directory')
    args = parser.parse_args(argv)
    try:
        d = MinionDaemon(args.workdir)
        d.run()
    except KeyboardInterrupt:
        sys.exit(0)
    except MinionException as e:
        print(e)
        sys.exit(1)

def main_tool(argv):
    sock_default = os.environ.get('MINION_SOCKET', './minion.sock')
    parser = argparse.ArgumentParser(prog='minion')
    parser.add_argument('--socket', type=str, default=sock_default,
                        help='socket to talk to minion daemon (default: %s)' % sock_default)
    subparsers = parser.add_subparsers(help='command-line tools')
    minion.cmd.update_heads(subparsers.add_parser('update-heads', help='fetch the latest sources'))
    minion.cmd.new_target(subparsers.add_parser('new-target', help='create a new build target'))
    minion.cmd.del_target(subparsers.add_parser('del-target', help='remove an existing build target'))
    minion.cmd.set_refspec(subparsers.add_parser('set-refspec', help='manually set the HEAD for a target/source pair'))
    minion.cmd.build(subparsers.add_parser('build', help='run the build process for a target (async)'))
    minion.cmd.status(subparsers.add_parser('status', help='check the status of a build'))
    minion.cmd.add_blob(subparsers.add_parser('add-blob', help='manually add a blob'))

    # run it
    if not argv:
        parser.print_help()
    else:
        args = parser.parse_args(argv)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        s.connect(args.socket)
        cmd = ' '.join([shlex.quote(arg) for arg in argv]) + '\n'
        s.sendall(cmd.encode('utf8'))
        s.shutdown(socket.SHUT_WR)
        data = b''
        while True:
            x = s.recv(512)
            if not x:
                break
            data += x
        output = json.loads(data.decode('utf8'))
        if 'output' in output:
            stdout = output['output']
            stdout = stdout.strip()
            stdout += '\n'
            sys.stdout.write(stdout)
        if output['status'] == 'success':
            sys.exit(0)
        else:
            sys.exit(1)
