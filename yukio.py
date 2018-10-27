#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re

DNS_PATTERN = 'alert udp $HOME_NET any -> any 53 (msg:"{} - {} - DNS request for {}"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:20; offset: 2; content:"{}"; flow:to_server; fast_pattern:only; nocase; classtype:trojan-activity; reference:url,{}; sid:{}; rev:1;)'
URL_PATTERN = 'alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"{} - {} - Related URL ({})"; content:"{}"; http_uri;{} flow:to_server,established; classtype:trojan-activity; reference:url,{}; sid:{}; rev:1;)'
TLS_PATTERN = 'alert tls $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"{} - {} - Related TLS SNI ({})"; tls_sni; content:"{}";flow:to_server,established; classtype:trojan-activity; reference:url,{}; sid:{}; rev:1;)'
MD5_PATTERN = 'alert tcp any [$HTTP_PORTS, 25] -> $HOME_NET any (msg:"{} - {} - MD5 hash found in blacklist {}"; classtype:trojan-activity; filestore; filemd5:{}; reference:url,{}; sid:{}; rev:1;)'
IP_TCP_PATTERN = 'alert tcp $HOME_NET any -> {} any (msg:"{} - {} - TCP traffic to {}"; flow:to_server,established; classtype:trojan-activity; reference:url,{}; sid:{}; rev:1;)'
IP_UDP_PATTERN = 'alert udp $HOME_NET any -> {} any (msg:"{} - {} - UDP traffic to {}"; classtype:trojan-activity; reference:url,{}; sid:{}; rev:1;)'
IP_PATTERN = 'alert ip $HOME_NET any -> {} any (msg:"{} - {} - IP traffic to {}"; classtype:trojan-activity; reference:url,{}; sid:{}; rev:1;)'


class Yukio:
    _sid_ = 0
    _org_ = ""

    def __init__(self, org, sid):
        if not sid or sid == "log":
            try:
                with open(
                        ".sid_log_file", "r",
                        encoding="utf-8") as f_sid_log_file:
                    line = f_sid_log_file.readline()
                    self._sid_ = int(line)
            except FileNotFoundError:
                print(
                    "[-] File .sid_log_file not found, starting SID from 5100000"
                )
                return
            except PermissionError as err:
                print(err)
                print("[+] Aborting! Please check against!")
                quit(0)
        else:
            self._sid_ = sid
        Yukio._org_ = org

    def __del__(self):
        try:
            with open(".sid_log_file", "w", encoding="utf-8") as f_sid:
                f_sid.write("{}".format(self._sid_))
        except PermissionError as err:
            print(err)
            print("[-] Warning, sid not saved")
            return false
        return True

    def genDnsRule(self, name, domain, ref):
        '''
        Gen rules for domain
        '''
        members = domain.split(".")
        dns_request = ""
        for member in members:
            dns_request += "|{:02X}|{}".format(len(member), member)
        rule = (DNS_PATTERN.format(self._org_, name, domain, dns_request, ref,
                                   self._sid_))
        self._sid_ += 1
        return rule, self._sid_ - 1

    def genUriRule(self, name, url, ref):
        '''
        Gen rules for URL
        '''
        uri = url.split("?")[0]
        uri_params = "?".join(url.split("?")[1:])
        rule_content = ""
        if uri_params:
            params = uri_params.split("&")
            rule_content = ' content:"?{}=";'.format(params[0].split("=")[0])
            for params in params[1:]:
                param = param.replace(';', r'|3b|')
                rule_content += ' content:"&{}=";'.format(param.split("=")[0])
        rule = (URL_PATTERN.format(self._org_, name, uri, url, rule_content,
                                   ref, self._sid_))
        self._sid_ += 1
        return rule, self._sid_ - 1

    def genIPRuleUdp(self, name, ipAddr, ref):
        '''
        Gen rule for IP, traffic over UDP
        '''
        rule = (IP_UDP_PATTERN.format(ipAddr, self._org_, name, ipAddr, ref,
                                      self._sid_))
        self._sid_ += 1
        return rule, self, _sid_ - 1

    def genIPRuleTcp(self, name, ipAddr, ref):
        '''
        Gen rule for IP, traffic over tcp
        '''
        rule = (IP_TCP_PATTERN.format(ipAddr, self._org_, name, ipAddr, ref,
                                      self._sid_))
        self._sid_ += 1
        return rule, self._sid_ - 1

    def genIPRule(self, name, ipAddr, ref):
        '''
        Gen rule for IP
        '''
        rule = (IP_PATTERN.format(ipAddr, self._org_, name, ipAddr, ref,
                                  self._sid_))
        self._sid_ += 1
        return rule, self._sid_ - 1

    def genTLSRule(self, name, domain, ref):
        '''
        Gen TLS SNI rule for domain
        '''
        rule = (TLS_PATTERN.format(self._org_, name, domain, domain, ref,
                                   self._sid_))
        self._sid_ += 1
        return rule, self._sid_ - 1

    def genMD5Rule(self, name, filePath, ref):
        rule = (MD5_PATTERN.format(self._org_, name,
                                   os.path.basename(filePath), filePath, ref,
                                   self._sid_))
        self._sid_ += 1
        return rule, self._sid_ - 1


def __split__line(line):
    (name, ref_url, ioc) = line.split(' ')
    name = name.strip()
    ref_url = ref_url.strip()
    ioc = ioc.strip()
    return name, ioc, ref_url


def __generate_rules__(genru, csv_file):
    try:
        with open(csv_file, "r") as f_input:
            rules = []
            for line in f_input:
                line = line.strip()
                (name, ioc, ref_url) = __split__line(line)
                if (ioc.startswith("/")
                        or ioc.startswith("http")) and not os.path.isfile(ioc):
                    print("a")
                    (rule, sid) = gen.genUriRule(name, ioc, ref_url)
                    rules.append(rule)
                elif os.path.isfile(ioc):
                    (rule, sid) = gen.genMD5Rule(name, ioc, ref_url)
                    rules.append(rule)
                elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ioc):
                    (rule, sid) = gen.genIPRule(name, ioc, ref_url)
                    rules.append(rule)
                    (rule, sid) = gen.genIPRuleUdp(name, ioc, ref_url)
                    rules.append(rule)
                    (rule, sid) = gen.genIPRuleTcp(name, ioc, ref_url)
                    rules.append(rule)
                else:
                    (rule, sid) = gen.genDnsRule(name, ioc, ref_url)
                    rules.append(rule)
                    (rule, sid) = gen.genUriRule(name, ioc, ref_url)
                    rules.append(rule)
                    (rule, sid) = gen.genTLSRule(name, ioc, ref_url)
                    rules.append(rule)
    except PermissionError as err:
        print(err)
        print("[+] Aborting, please check!!!")
        quit(0)
    return rules


def main(args):
    gen = Yukio(args.emitter, args.ssid)
    if args.output:
        print("[+] Generating rules automatic")
    rules = __generate_rules__(gen, args.file)
    if args.output:
        print("[+] Writing Rule Automatic")
        try:
            with open(args.output, "a") as f_out:
                for rule in rules:
                    f_out.write("{} \n".format(rule))
        except PermissionError:
            print("[+] Can't write rule file, permission denied")
            print("[+ ] Rules not saved, be carefull")
    else:
        for rule in rules:
            print("{}".format(rule))


if __name__ == '__main__':
    __parser__ = argparse.ArgumentParser()
    __parser__.add_argument("file", help="Input file")
    __parser__.add_argument("--output", "-o", help="Writing result to file")
    __parser__.add_argument(
        "--ssid", "-s", help="Starting sid of the generated rules", type=int)
    __parser__.add_argument(
        "--emitter",
        "-e",
        help="Emitter of the rules, default: Yukio",
        default="yukio")
    __args__ = __parser__.parse_args()
    main(__args__)
