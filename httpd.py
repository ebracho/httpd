#!/usr/bin/env python3.6

import socket
import os
from collections import namedtuple

# namedtuples for now, will eventually move to classes
HttpRequest = namedtuple('HttpRequest', ['method', 'location', 'protocol', 'headers'])
HttpResponse = namedtuple('HttpResponse', ['protocol', 'code', 'msg', 'body'])

def parse_http_req(data):
	lines = [l.strip() for l in data.strip().split('\n')]
	if len(lines) == 0:
		return HttpRequest('', '', '', '') # Malformed request, will handled later
	status_line, headers = lines[0], lines[1:]
	headers = dict(h.split(': ') for h in headers)
	return HttpRequest(*status_line.split(), headers)

def build_response(req):
	filepath = os.path.realpath(os.path.join(os.getcwd(), req.location[1:] or 'index.html'))
	if not all([req.method, req.location, req.protocol]):
		return HttpResponse(req.protocl, 400, 'Malformed request', '')
	if not filepath.startswith(os.getcwd()):
		return HttpResponse(req.protocol, 401, 'Unauthorized', '')
	elif not os.path.isfile(filepath):
		return HttpResponse(req.protocol, 404, 'File not found', '')
	else:
		with open(filepath, 'r') as f:
			return HttpResponse(req.protocol, 200, 'OK', f.read())

def handle_conn(conn, addr):
	with conn:
		data = conn.recv(4096)
		req = parse_http_req(data.decode('utf-8'))
		res = build_response(req)
		conn.sendall(f'{res.protocol} {res.code} {res.msg}\n\n{res.body}'.encode())

HOST = ''
PORT = 3333
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.bind((HOST, PORT))
	s.listen(1)
	handle_conn(*s.accept())

