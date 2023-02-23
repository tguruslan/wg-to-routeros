#!/usr/bin/env python

import sys
import configparser
import ipaddress
import socket
from io import StringIO

class ConfigParserMultiOpt(configparser.RawConfigParser):
  def __init__(self):
    configparser.RawConfigParser.__init__(self, empty_lines_in_values=False, strict=False)

  def _read(self, fp, fpname):
    elements_added = set()
    cursect = None
    sectname = None
    optname = None
    lineno = 0
    indent_level = 0
    e = None
    for lineno, line in enumerate(fp, start=1):
      comment_start = None
      for prefix in self._inline_comment_prefixes:
        index = line.find(prefix)
        if index == 0 or (index > 0 and line[index-1].isspace()):
          comment_start = index
          break
      for prefix in self._comment_prefixes:
        if line.strip().startswith(prefix):
          comment_start = 0
          break
      value = line[:comment_start].strip()
      if not value:
        if self._empty_lines_in_values:
          if (comment_start is None and
              cursect is not None and
              optname and
              cursect[optname] is not None):
              cursect[optname].append('')
        else:
          indent_level = sys.maxsize
        continue
      # continuation line?
      first_nonspace = self.NONSPACECRE.search(line)
      cur_indent_level = first_nonspace.start() if first_nonspace else 0
      if (cursect is not None and optname and
          cur_indent_level > indent_level):
          cursect[optname].append(value)
      else:
        indent_level = cur_indent_level
        # is it a section header?
        mo = self.SECTCRE.match(value)
        if mo:
          sectname = mo.group('header')
          if sectname in self._sections:
            if self._strict and sectname in elements_added:
              raise DuplicateSectionError(sectname, fpname,
                                          lineno)
            cursect = self._sections[sectname]
            elements_added.add(sectname)
          elif sectname == self.default_section:
            cursect = self._defaults
          else:
            cursect = self._dict()
            self._sections[sectname] = cursect
            self._proxies[sectname] = configparser.SectionProxy(self, sectname)
            elements_added.add(sectname)
          optname = None
        elif cursect is None:
          raise MissingSectionHeaderError(fpname, lineno, line)
        else:
          mo = self._optcre.match(value)
          if mo:
            optname, vi, optval = mo.group('option', 'vi', 'value')
            if not optname:
              e = self._handle_error(e, fpname, lineno, line)
            optname = self.optionxform(optname.rstrip())
            if (self._strict and
              (sectname, optname) in elements_added):
              raise configparser.DuplicateOptionError(sectname, optname, fpname, lineno)
            elements_added.add((sectname, optname))
            if optval is not None:
              optval = optval.strip()
              if (optname in cursect) and (cursect[optname] is not None):
                if not isinstance(cursect[optname], tuple):
                  cursect[optname] = tuple(cursect[optname])
                cursect[optname] = cursect[optname] + tuple([optval])
              else:
                cursect[optname] = [optval]
            else:
                cursect[optname] = None
          else:
            e = self._handle_error(e, fpname, lineno, line)
    if e:
        raise e
    self._join_multiline_values()


def generate():
    config = ConfigParserMultiOpt()
    config.read(sys.argv[1])
    has_ipv6=False

    d_name = sys.argv[2]
    privatekey = config.get('Interface', 'PrivateKey')
    publickey = config.get('Peer', 'PublicKey')
    endpoint = config.get('Peer', 'Endpoint')

    address = str(config.get('Interface', 'Address')).replace(' ', '').replace('(', '').replace(')', '').replace("'", '')
    allowedips = str(config.get('Peer', 'AllowedIPs')).replace(' ', '').replace('(', '').replace(')', '').replace("'", '')

    output = StringIO()

    output.write('/routing table add disabled=no fib name={}\n'.format(d_name))
    output.write('/interface wireguard add listen-port=13231 mtu=1280 name={}  private-key="{}"\n'.format(
        d_name,
        privatekey
    ))
    output.write('/interface wireguard peers add allowed-address={} endpoint-address={} endpoint-port={} interface={} public-key="{}"\n'.format(
        allowedips,
        socket.gethostbyname(endpoint.split(':')[0]),
        endpoint.split(':')[1],
        d_name,
        publickey,
    ))
    for ip in address.split(","):
      if type(ipaddress.ip_address(ip.split('/')[0])) is ipaddress.IPv4Address:
        output.write('/ip address add address={} interface={} network={}\n'.format(
            ip,
            d_name,
            str(ipaddress.ip_network(ip, strict=False)).split('/')[0]
        ))
      else:
        has_ipv6=True
        output.write('/ipv6 address add address={} advertise=no interface={}\n'.format(
            ip,
            d_name
        ))
    output.write('/ip firewall nat add action=masquerade chain=srcnat out-interface={}\n'.format(d_name))
    output.write('/ip firewall mangle add action=mark-routing chain=prerouting dst-address-list={} new-routing-mark={} passthrough=no\n'.format(
        d_name,
        d_name
    ))
    output.write('/ip route add disabled=no distance=1 dst-address=0.0.0.0/0 gateway={} pref-src="" routing-table={} scope=30 suppress-hw-offload=no target-scope=10\n'.format(
        d_name,
        d_name,
    ))

    if has_ipv6:
      output.write('/ipv6 firewall nat add action=masquerade chain=srcnat out-interface={}\n'.format(d_name))
      output.write('/ipv6 firewall mangle add action=mark-routing chain=prerouting dst-address-list={} new-routing-mark={} passthrough=no\n'.format(
          d_name,
          d_name
      ))
      output.write('/ipv6 route add disabled=no distance=1 dst-address=::/0 gateway={} routing-table={} scope=30 target-scope=10\n'.format(
          d_name,
          d_name,
      ))

    for a_ip in allowedips.split(','):
      if type(ipaddress.ip_address(a_ip.split('/')[0])) is ipaddress.IPv4Address:
        output.write('/ip firewall address-list add address={} list={}\n'.format(
            a_ip,
            d_name
        ))
      else:
        output.write('/ipv6 firewall address-list add address={} list={}\n'.format(
            a_ip,
            d_name
        ))

    return output.getvalue()


if __name__ == '__main__':
    if len(sys.argv) > 3:
        with open(sys.argv[3],'w') as out:
            out.write(generate())
    else:
        print(generate())

