#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re

parser = argparse.ArgumentParser()
parser.add_argument("rules", help="Rules file to analyze")
parser.add_argument(
    "--report",
    help=
    "Rule field: action,protocol,source,sourcePort,destination,destinationPort,header,option"
)
parser.add_argument(
    "--criteria",
    help=
    "String criteria that needs to match a field in the report output that will initiate the printing of the rule"
)
args = parser.parse_args()
rules = open(args.rules)
rule = rules.readline()
rawCount = 0
count = 0
while rule:
    rawCount = rawCount + 1
    if not rule.startswith("#") and not rule.startswith("\n"):
        count = count + 1
        spaceTokens = re.split(" +", rule)
        action = spaceTokens[0]
        protocol = spaceTokens[1]
        source = spaceTokens[2]
        sourcePort = spaceTokens[3]
        direction = spaceTokens[4]
        destination = spaceTokens[5]
        destinationPort = spaceTokens[6]
        header = action + " " + protocol + " " + source + " " + sourcePort + " " + direction + " " + destination + " " + destinationPort + " "
        optionsArr = re.split(" \(", rule)
        options = re.sub("\)$", "", optionsArr[1])
        if args.report == "action":
            if args.criteria is not None and args.criteria in action:
                print(action + ": " + rule)
            elif args.criteria is None:
                print(action)
        elif args.report == "protocol":
            if args.criteria is not None and args.criteria in protocol:
                print(protocol + ": " + rule)
            elif args.criteria is None:
                print(protocol)
        elif args.report == "source":
            sourceSplit = re.sub("\[", "", source)
            sourceSplit = re.sub("\]", "", sourceSplit)
            sources = sourceSplit.split(",")
            for src in sources:
                if args.criteria is not None and args.criteria in src:
                    print(src + ": " + rule)
                elif args.criteria is None:
                    print(src)
        elif args.report == "sourcePort":
            sourcePortSplit = re.sub("\[", "", sourcePort)
            sourcePortSplit = re.sub("\]", "", sourcePortSplit)
            sourcePorts = sourcePortSplit.split(",")
            for srcPort in sourcePorts:
                if args.criteria is not None and args.criteria in srcPort:
                    print(srcPort + ": " + rule)
                elif args.criteria is None:
                    print(srcPort)
        elif args.report == "direction":
            if args.criteria is not None and args.criteria in direction:
                print(direction + ": " + rule)
            elif args.criteria is None:
                print(direction)
        elif args.report == "destination":
            destinationSplit = re.sub("\[", "", destination)
            destinationSplit = re.sub("\]", "", destinationSplit)
            destinations = destinationSplit.split(",")
            for dst in destinations:
                if args.criteria is not None and args.criteria in dst:
                    print(dst + ": " + rule)
                elif args.criteria is None:
                    print(dst)
        elif args.report == "destinationPort":
            destinationPortSplit = re.sub("\[", "", destinationPort)
            destinationPortSplit = re.sub("\]", "", destinationPortSplit)
            destinationPorts = destinationPortSplit.split(",")
            for dstPort in destinationPorts:
                if args.criteria is not None and args.criteria in dstPort:
                    print(dstPort + ": " + rule)
                elif args.criteria is None:
                    print(dstPort)
        elif args.report == "header":
            if args.criteria is not None and args.criteria in header:
                print(header + ": " + rule)
            elif args.criteria is None:
                print(header)
        elif args.report == "option":
            fieldValues = options.split("; ")
            for fieldValue in fieldValues:
                if args.criteria is not None and args.criteria in fieldValue:
                    print(fieldValue + ": " + rule)
                elif args.criteria is None:
                    print(fieldValue)
        elif args.report == "etcat":
            fieldValues = options.split("; ")
            for fieldValue in fieldValues:
                if fieldValue.startswith("msg:"):
                    etcat = re.sub("msg:", "", fieldValue)
                    etcat = re.match(r"\"([A-Z\-\_\s+]+\s)", etcat)
                    print(etcat[1])
    rule = rules.readline()
rules.close()
