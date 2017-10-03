#!/usr/bin/env python3.6

import socket
import os
import mimetypes
from concurrent.futures import ThreadPoolExecutor


HOST = ''
PORT = 3333
MAX_THREADS = 1024


class Request:
	def __init__(self, conn, addr):
		self.conn = conn
		self.addr = addr
		self.data = conn.recv(4096).decode('utf-8')
		self.method, self.path, self.protocol, self.headers, self.body = self._parse_data()

	# TODO: Better parsing
	def _parse_data(self):
		headers, body = self.data.split('\r\n\r\n')
		lines = [l.strip() for l in headers.strip().split('\n')]
		status_line, headers = lines[0], lines[1:]
		method, path, protocol = status_line.split()
		headers = dict(h.split(': ') for h in headers)
		return method, path, protocol, headers, body

	def __str__(self):
		return f'[{self.addr[0]}] {self.method} {self.path} {self.protocol}'


class Response:
	def __init__(self, req):
		self.req = req
		self.protocol, self.code, self.msg, self.headers, self.body = self._build()

	def _build(self):
		if not all([self.req.method, self.req.path, self.req.protocol]):
			return ('HTTP/1.1', 400, 'Bad request', {}, b'')
		fp = os.path.realpath(os.path.join(os.getcwd(), self.req.path[1:] or 'index.html'))
		if not fp.startswith(os.getcwd()):
			return (self.req.protocol, 403, 'Forbidden',  {}, b'')
		elif not os.path.isfile(fp):
			return (self.req.protocol, 404, 'Not Found', {}, b'')
		else:
			with open(fp, 'rb') as f:
				body = f.read()
				headers = {
					'Content-Length': len(body),
				}
				content_type, _ = mimetypes.guess_type(fp)
				if content_type:
					headers['Content-Type'] = f'{content_type};'
				return (self.req.protocol, 200, 'OK', headers, body)

	def send(self):
		with self.req.conn:
			status_line = f'{self.protocol} {self.code} {self.msg}'
			headers = [f'{k}: {v}' for k,v in self.headers.items()]
			payload = ('\r\n'.join([status_line] + headers) + '\r\n\r\n').encode('utf-8') + self.body
			self.req.conn.sendall(payload)

	def __str__(self):
		return f'{self.protocol} {self.code} {self.msg}'


def handle_conn(conn, addr):
	req = Request(conn, addr)
	res = Response(req)
	res.send()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.bind((HOST, PORT))
	s.listen(2)
	with ThreadPoolExecutor(MAX_THREADS) as ex:
		while True:
			ex.submit(handle_conn, *s.accept())
