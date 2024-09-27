from concurrent.futures import Future, ThreadPoolExecutor
import io
import json
import os
import re
import socket
import ssl
import sys
import threading
from typing import Any, Iterable

_f_opts = {
	"dot_retries": 3,
	"dot_port": 853,
	"dot_ssl_ctx_f": ssl.create_default_context,
	"dot_timeout": 2.0,
	"dot_nproc": 500,
	"dot_result_f": None
}

_argv0 = "scandotns"

def parse_zonefile (f: io.TextIOBase, opts = None) -> tuple[dict[str, set[str]], set[str]]:
	tld_ns_map = dict[str, set[str]]()
	ns_set = set[str]()

	while True:
		line = f.readline()
		if not line:
			break
		line = line.strip()

		if line.startswith('#'):
			continue

		row = re.split(r'\t+', line)
		if len(row) != 5:
			continue

		rname = row[0].lower()
		rclass = row[2].upper()
		rtype = row[3].upper()
		rr = row[4].lower()

		if False:
			if rname == '.':
				# ignore root
				continue
		if rname.find('.') != rname.rfind('.'):
			# ignore non-tld
			continue
		if rclass != "IN":
			# ignore non-internet class
			continue
		if rtype != "NS":
			# ignore everything else
			continue

		ns_set.add(rr)
		s = tld_ns_map.get(rname)
		if s:
			s.add(rr)
		else:
			n = set()
			n.add(rr)
			tld_ns_map[rname] = n

	return (tld_ns_map, ns_set)

def _try_ns_dot_inner (host: str, opts: dict[str, Any]) -> dict[str, Any]:
	ret = {}
	err = None
	port = opts["dot_port"]
	sslctx = opts["dot_ssl_ctx_f"]()

	for i in range(0, opts["dot_retries"]):
		try:
			sslctx.check_hostname = True
			sslctx.verify_mode = ssl.CERT_REQUIRED
			with socket.create_connection((host, port), opts["dot_timeout"]) as sck:
				with sslctx.wrap_socket(sck, server_hostname = host) as ss:
					ret["ssl_ver"] = ss.version()
					ret["ssl_attr"] = [ "SNI", "CERT" ]
					break
		except Exception as e:
			err = str(e)

		try:
			sslctx.check_hostname = False
			sslctx.verify_mode = ssl.CERT_NONE
			with socket.create_connection((host, port), opts["dot_timeout"]) as sck:
				with sslctx.wrap_socket(sck, server_hostname = host) as ss:
					ret["ssl_ver"] = ss.version()
					ret["ssl_attr"] = []
					break
		except Exception as e:
			err = str(e)

	ret["error"] = err
	if opts["dot_result_f"]:
		opts["dot_result_f"](host, port, ret)
	return ret

def try_ns_dot (it: Iterable[str], nb_it: int, opts = None) -> dict[str, Any]:
	ret = dict[str, Any]()
	fmap = dict[str, Future[tuple[dict[str, Any], str]]]()

	l = threading.Lock()
	cnt = 0
	report_int = int(nb_it / 20) # every 5%
	if report_int == 0: report_int = 1

	def _try_ns_dot_result_f (ns: str, port: int, obj: dict[str, Any]):
		global _argv0
		nonlocal l
		nonlocal cnt
		nonlocal report_int

		l.acquire()
		try:
			if cnt % report_int == 0:
				sys.stderr.write(_argv0 + ": {} / {} ({:.1f}%)".format(
					cnt,
					nb_it,
					float(cnt) / float(nb_it) * 100.0) + os.linesep)

			if obj.get("ssl_ver") or (False): # TODO: verbosity option
				sys.stderr.write(_argv0 + ": {}:{}: {}".format(ns, port, str(obj)) + os.linesep)
		finally:
			cnt += 1
			l.release()

	if opts is None:
		opts = _f_opts
	else:
		opts = { **_f_opts, **opts }
	opts["dot_result_f"] = _try_ns_dot_result_f

	with ThreadPoolExecutor(opts["dot_nproc"]) as tp:
		for ns in it:
			fmap[ns] = tp.submit(_try_ns_dot_inner, ns, opts)

	for ns, fut in fmap.items():
		ret[ns] = fut.result()

	return ret


def create_result_map (map: dict[str, set[str]], result: dict[str, Any]) -> dict[str, Any]:
	ret = dict[str, Any]()

	for k, v in map.items():
		obj = {}
		for ns in v:
			# filter out null results
			r = result.get(ns)
			if r and r.get("ssl_ver"):
				obj[ns] = r
		if obj:
			ret[k] = obj

	return ret

# load TLD nameservers from the root zone file
with open("root.zone") as f:
	tld_ns_map, ns_set = parse_zonefile(f)

# scan 853/TCP
result = try_ns_dot(ns_set, len(ns_set))
# merge result to the original TLD-NS map
out = create_result_map(tld_ns_map, result)

json.dump(out, sys.stdout, indent = '\t')
print()
