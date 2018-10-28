#!/usr/bin/python
"""

"""

import collections


class Store:
    """ """
    def __init__(self):
        """ """

    def read_input(self, infi):
        """Return contents from file as a list"""
        opfi = open(infi, "r")
        fico = opfi.read().splitlines()
        opfi.close()

        return fico

class Report:
    """ """
    def __init__(self):
        """ """

    def flat_data(self, csv_data, resource_type):
        """Generate report formatted as a flat text file"""
        ordi = collections.OrderedDict()

        for row in csv_data[1:]:
            key = row.split(",")[0]
            if resource_type == "c":
                key = row.split(",")[4]

            if key in ordi:
                ordi[key] = ordi[key] + [row.split(",")]
            else:
                ordi[key] = [row.split(",")]

        fida = []
        for _, vs in ordi.items():
            for index in range(len(vs[0])):
                spio = []
                for v in vs:
                    if v[index] != "download skipped" and \
                        v[index] != "file never seen" and \
                        v[index] != "file not submitted" and \
                        v[index] != "Unknown":
                        spio.append(v[index].split(" | "))
                fiio = filter(None, sum(spio, []))
                if len(fiio) == 0: continue
                unio = sorted(set(fiio))
                liio = "\n\t".join(unio)

                fida.append("%s" % headers.split(",")[index])
                fida.append("\t%s" % liio)
            fida.append("\n-----------------------------\n")

        return fida
