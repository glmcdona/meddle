from threading import *
import csv
import os

class capture:
	def __init__(self, filename, headers):
		self.file = open(filename, "wb")
		self.writer = csv.DictWriter(self.file, headers)
		self.lock = Lock()
		
	def log_event(self, fields):
		self.lock.acquire()

		try:
			self.writer.writerow(fields)
			self.file.flush()
		finally:
			self.lock.release()

class sandbox_logfile:
	def __init__(self, path, prefix):
		self.path = path
		self.prefix = prefix
		self.pid_files = {}
		self.lock = Lock()
		
	def log_event(self, pid, data):
		self.lock.acquire()

		try:
			if str(pid) in self.pid_files:
				fh = self.pid_files[str(pid)]
			else:
				filename = os.path.join(self.path, "%s_%s.log" % (self.prefix, str(pid) ))
				fh = open(filename, "wb")
				self.pid_files[str(pid)] = fh

			fh.write(data)
			fh.flush()
		finally:
			self.lock.release()