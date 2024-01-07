"""
Python script that converts Burp Suite HTTP proxy history files to CSV or HTML files
"""
from __future__ import unicode_literals
from __future__ import print_function

import sys
import io
import argparse
import html
import json
import base64

import xmltodict
from backports import csv
from http import client as httpClient

_g_csv_delimiter = ','


def main():
    args = parse_arguments()
    set_csv_delimiter(args.csv_delimiter)
    format_handler = FORMATS[args.format](args.filename)
    http_history = parse_http_history(args.filename)
    convert_to_output_file(http_history, format_handler)


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filename', help='Burp Suite HTTP proxy history file')
    parser.add_argument('--format', default='html', choices=FORMATS.keys(),
                        help='output format, default: html')
    parser.add_argument('--csv-delimiter', choices=(',', ';'),
                        help='CSV delimiter, default: ,')
    return parser.parse_args()


def convert_to_output_file(http_history, format_handler):
    with io.open(format_handler.filename, 'w', encoding='utf-8', newline='') as output_file:
        format_handler.set_output_file(output_file)
        format_handler.header_prefix()
        format_handler.header_column('Time')
        format_handler.header_column('URL')
        format_handler.header_column('Hostname')
        format_handler.header_column('IP address')
        format_handler.header_column('Port')
        format_handler.header_column('Protocol')
        format_handler.header_column('Method')
        format_handler.header_column('Path')
        format_handler.header_column('Extension')
        format_handler.header_column('Request')
        format_handler.header_column('Status')
        format_handler.header_column('Response length')
        format_handler.header_column('MIME type')
        format_handler.header_column('Response')
        format_handler.header_column('Comment')
        format_handler.header_suffix()
        for line in http_history['items']['item']:
            format_handler.row_prefix()
            format_handler.row_column(line['time'])
            format_handler.row_column(line['url'])
            format_handler.row_column(line['host']['#text'])
            format_handler.row_column(line['host']['@ip'])
            format_handler.row_column(line['port'])
            format_handler.row_column(line['protocol'])
            format_handler.row_column(line['method'])
            format_handler.row_column(line['path'])
            format_handler.row_column(line['extension'])
            if '#text' in line['request']:
                format_handler.row_column(line['request']['#text'], encoded=True)
            else:
                format_handler.row_column("None")
            format_handler.row_column(line['status'])
            format_handler.row_column(line['responselength'])
            format_handler.row_column(line['mimetype'])
            if '#text' in line['response']:
                format_handler.row_column(line['response']['#text'], encoded=True)
            else:
                format_handler.row_column("None")
            format_handler.row_column(line['comment'])
            format_handler.row_suffix()
        format_handler.footer()


def parse_http_history(filename):
    with open(filename, 'rb') as f:
        return xmltodict.parse(f)


def base64decode(line):
    decoded = base64.b64decode(line)
    replace = 'backslashreplace' if sys.version_info[0] >= 3 else 'replace'
    return decoded.decode('UTF-8', errors=replace)


def set_csv_delimiter(csv_delimiter):
    if csv_delimiter:
        global _g_csv_delimiter
        _g_csv_delimiter = unicode(csv_delimiter)


class FormatHandlerBase(object):
    def __init__(self, filename):
        self.filename = filename + self.FILENAME_SUFFIX


class HtmlFormatHandler(FormatHandlerBase):
    FILENAME_SUFFIX = '.html'
    HEADER = '''<!DOCTYPE html>
<html>
    <head>
    <title>Burp Suite proxy history</title>
    <style>
    table {
        border-collapse: collapse;
    }
    table, th, td {
        border: 1px solid black;
        font-family: Arial, sans-serif;
        padding: 5px;
    }
    th {
        text-align: left;
    }
    td {
        vertical-align: top;
    }
    </style>
    </head>
    <body>
        <table><thead><tr>
'''
    FOOTER = '''</tbody></table>
</body></html>
'''

    def set_output_file(self, output_file):
        self.output_file = output_file

    def header_prefix(self):
        print(self.HEADER,
              file=self.output_file)

    def header_suffix(self):
        print('</tr></thead><tbody>',
              file=self.output_file)

    def header_column(self, column_name):
        print('<th>%s</th>' % column_name,
              file=self.output_file)

    def row_prefix(self):
        print('<tr>', file=self.output_file)

    def row_suffix(self):
        print('</tr>', file=self.output_file)

    def row_column(self, content, encoded=False):
        template = '<td>%s</td>' if not encoded else '<td><pre>%s</pre></td>'
        if encoded:
            content = html.escape(base64decode(content))
        print(template % content,
              file=self.output_file)

    def footer(self):
        print(self.FOOTER,
              file=self.output_file)


# note that total number of characters that an Excel cell can contain is 32,760
class CsvFormatHandler(FormatHandlerBase):
    FILENAME_SUFFIX = '.csv'

    def set_output_file(self, output_file):
        self.writer = csv.writer(output_file, dialect='excel',
                                 delimiter=_g_csv_delimiter)
        self.header = []

    def header_prefix(self):
        pass

    def header_suffix(self):
        self.writer.writerow(self.header)

    def header_column(self, column_name):
        self.header.append(column_name)

    def row_prefix(self):
        self.row = []

    def row_suffix(self):
        self.writer.writerow(self.row)

    def row_column(self, content, encoded=False):
        if content and encoded:
            content = base64decode(content)
        # total number of characters that an Excel cell can contain is 32,760
        if content and len(content) > 32760:
            content = content[:32744] + '..[TRUNCATED!]'
        self.row.append(content)

    def footer(self):
        pass

class JsonFileFormatHandler(FormatHandlerBase):
  FILENAME_SUFFIX = '.json'
  """
  JsonFileFormatHandler is used to split the capture into multiple json files for each request/response.
  3 files are generated: 
      - one that holds the captured meta-information (named timestamp-index.json)
      - one that holds the request (named timestmap-index.req.json)
      - one that holds the response (named timestamp-index.res.json)
  All files are pretty-printed json files with sorted keys so that it's easy to jump between files and pick up changes.
  """
  def set_output_file(self, output_file):
    self.baseFile = output_file.name[:-4]
    self.rowIndex = 0

  def header_prefix(self):
      self.header = []
    
  def header_suffix(self):
      pass
    
  def header_column(self, column_name):
      self.header.append(column_name)
    
  def row_prefix(self):
      self.fileData = {"index": self.rowIndex}
      self.colIndex = 0
    
  def jsonFromHttp(self, string):
    """
    Parse a request or response-string and return a json representation.
    First line of the string is either a HTTP-Request line (GET /foo) or a response (HTTP1/1 200 Success).
    This line is reported as "method" and "url" (for both requests and responses)
    The actual body is provided via "body" key.
    """
    if not string:
      return {}
    requestLine, rest = string.split('\r\n', 1)
    # split the first line, it cannot be parsed by the parse_headers() function
    method, url = requestLine.split(" ",1)
    byteStream = io.BytesIO(rest.encode("utf-8"))
    message = httpClient.parse_headers(byteStream)
    body = byteStream.read().decode("utf-8")
    res = {"method":method, "url": url}
    for key in message.keys():
      res[key] = message[key]
    res["body"] = body
    return res
  
  def writeJsonFile(self, fileName, dictionary):
    with open(fileName,"w") as f:
        f.write(json.dumps(dictionary, sort_keys=True, indent=1))

  def row_suffix(self):
    timePart = self.fileData['Time']
    timePart = timePart.replace(":", "")
    timePart = timePart.replace(" ", "_")
    self.writeJsonFile(F"{self.baseFile}_{timePart}_{self.rowIndex}.json",self.fileData)
    self.writeJsonFile(F"{self.baseFile}_{timePart}_{self.rowIndex}.req.json",self.jsonFromHttp(self.request))
    self.writeJsonFile(F"{self.baseFile}_{timePart}_{self.rowIndex}.res.json",self.jsonFromHttp(self.response))
    self.rowIndex += 1

  def row_column(self, content, encoded=False):
      if content and encoded:
          content = base64decode(content)
      colName = self.header[self.colIndex]
      if colName == "Request":
        self.request = content
      elif colName == "Response":
        self.response = content
      else:
        self.fileData[colName] = content
      self.colIndex += 1
        
    
  def footer(self):
      pass
    

FORMATS = {
    'html': HtmlFormatHandler,
    'csv': CsvFormatHandler,
    'json': JsonFileFormatHandler,
}

if __name__ == '__main__':
    # In python 3, unicode is renamed to str
    if sys.version_info[0] >= 3:
      unicode = str
    main()
  
