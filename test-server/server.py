#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import argparse

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Connection', 'close')
        self.end_headers()

        message = f"Server address: {self.server.server_address[0]}:{self.server.server_address[1]}\n"
        self.wfile.write(message.encode())
        message = f"Client {self.client_address[0]}:{self.client_address[1]}\n\n"
        self.wfile.write(message.encode())


def main():
    parser = argparse.ArgumentParser(description='My Program')
    parser.add_argument('-p', '--port', type=int, help='Port number', required=True)
    args = parser.parse_args()

    server_address = ('', args.port)
    httpd = HTTPServer(server_address, MyHandler)
    print("Serving at port", args.port)
    httpd.serve_forever()

if __name__ == "__main__":
    main()
