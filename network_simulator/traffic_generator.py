import iperf3
import csv

def run(server_hostname, server_port, duration, bandwidth):
	client = iperf3.Client()
	client.server_hostname = server_hostname
	client.port = server_port
	client.duration = duration
	client.bandwidth = bandwidth
	result = client.run()
			

if __name__ == "__main__":
	file_path = "config.csv"
	with open(file_path, newline='') as csvfile:
		csvreader = csv.DictReader(csvfile)
		for row in csvreader:
			server_hostname = row["dst_ip"]
			server_port = int(row["port"])
			duration = int(row["time"])
			bandwidth = 8*1024*int(row["bandwidth"])
			run(server_hostname, server_port, duration, bandwidth)


	