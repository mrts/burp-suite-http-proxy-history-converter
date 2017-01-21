# burp-suite-http-proxy-history-converter

Python script that converts Burp Suite HTTP proxy history files to HTML or CSV.

## Usage

Download the script and install requirements:

    $ git clone https://github.com/mrts/burp-suite-http-proxy-history-converter.git
    $ cd burp-suite-http-proxy-history-converter
    $ pip install --requirement=requirements.txt

Usage overview:

    $ python convert-burp-suite-http-proxy-history-to-csv.py -h
    usage: convert-burp-suite-http-proxy-history-to-csv.py [-h]
                                                           [--format {html,csv}]
                                                           [--csv-delimiter {,,;}]
                                                           filename

    Python script that converts Burp Suite HTTP proxy history files to CSV or HTML
    files

    positional arguments:
      filename              Burp Suite HTTP proxy history file

    optional arguments:
      -h, --help            show this help message and exit
      --format {html,csv}   output format, default: html
      --csv-delimiter {,,;}
                            CSV delimiter, default: ,

Convert Burp Suite HTTP proxy history file to HTML, output will be next to input
file with `.html` extension:

    python convert-burp-suite-http-proxy-history-to-csv.py /path/to/burp_http_history.xml

Convert Burp Suite HTTP proxy history file to CSV using `;` as delimiter, output
will be next to input file with `.csv` extension:

    python convert-burp-suite-http-proxy-history-to-csv.py /path/to/burp_http_history.xml \
        --format csv --csv-delimiter ';'

**Note that CSV file fields are truncated to 32760 characters as that is the
total number of characters that an Excel cell can contiain.**
