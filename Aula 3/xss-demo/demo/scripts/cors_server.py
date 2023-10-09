#!/usr/bin/env python3
"""
Small 'CORS' enabled server that outputs several CORS
"""
from http.server import (
    HTTPServer,
    BaseHTTPRequestHandler,
    )
import urllib
import datetime
import os


class CustomRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        fname = self.path.split("/")[1]
        
        if os.path.exists(fname):
            self.send_response(200)
            #if fname.endswith('.jpg'):
            #    self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
                
            print("Serving file: {}".format(fname))
            extension = fname.split(".")[-1]
            content_type = {'js': 'application/javascript', 'jpg': 'image/jpg', 'ttf': 'font'}.get(extension, 'text/txt')
            self.send_header('Content-type',content_type)

            with open(fname, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()

    def handle(self):
        super().handle()
        print("Request Debug: ", self.command)
        print(self.headers)
        

def main():
    server_class = HTTPServer
    handler_class = CustomRequestHandler
    server_address = ('', 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


if __name__ == '__main__':
    main()

