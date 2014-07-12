from threading import *
import csv

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