#!/usr/bin/python
"""

"""

from collections import OrderedDict
from re import findall

from flask import Flask, abort, redirect, render_template, request
from werkzeug.urls import iri_to_uri

from web_worker import Store, Report


app    = Flask(__name__)
store  = Store()
report = Report()

@app.route("/")
def index():
    """ """
    line = return_lines("/", "application/", "csv")
    fity = line[1].split(",")[2]
    chsu = line[1].split(",")[3]

    if chsu == "" or not fity.startswith("application/"):
        chsu = line[1].split(",")[6]
        if chsu == "":
            return render_template("index.html", sena="osweep.io:443", chsu="{IOC}")
        else:
            return render_template("index.html", sena="osweep.io:443", chsu=chsu)

@app.route("/<file_type>")
def return_all(file_type):
    """ """
    if file_type == "csv":    oufi = ""
    elif file_type == "text": oufi = ""
    elif file_type == "feed": oufi = ""
    else:                     return abort(404)

    rein = store.read_input(oufi)
    enin = [x.decode("utf-8") for x in rein]
    foco = "\n".join(enin)

    return render_template("response.html", text=foco)

@app.route("/<file_type>/<search>")
def return_hash(file_type, search):
    """ """
    if file_type != "csv" and file_type != "text" and file_type != "feed": return abort(404)

    rout = "/%s/%s" % (file_type, search)
    iobh = return_lines(rout, search, file_type)
    if len(iobh) < 2: abort(400)
    requ = "\n".join(iobh)

    if file_type == "text":
        unfd = report.flat_data(iobh, None)
        requ = "\n".join(unfd)

    return render_template("response.html", text=requ.decode("utf-8"))

@app.errorhandler(404)
def error_client(error):
    """ """
    return render_template("error_client.html"), 404

@app.errorhandler(500)
def error_server(error):
    """ """
    return render_template("error_server.html"), 500

@app.errorhandler(400)
def error_request(error):
    """ """
    return render_template("error_request.html"), 400

def return_lines(route, search, file_type):
    """ """
    oufi = ""
    if file_type == "feed": oufi = "web_worker.py"

    rein  = store.read_input(oufi)
    lines = []
    lines.append(rein[0])

    for line in rein:
        if search.lower() in line.decode("utf-8").lower(): 
            lines.append(line)
            if route == "/": break

    return lines

app.run(host="osweep.io", port=443, threaded=True)
