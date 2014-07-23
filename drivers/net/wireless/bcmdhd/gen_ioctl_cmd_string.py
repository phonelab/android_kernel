#!/usr/bin/python

# Generate C macro strings for wl ioctl commands
# usage: def.py [src header] [dst c file]

import sys, re

def_file = sys.argv[1]
print "Input file: %s" % (def_file)

c_file = open(sys.argv[2], 'w')
print "Ouput file: %s" % (c_file)

print >>c_file, "const char* WLC_CMD_NAME[512] = {"

with open(def_file, 'r') as f :
  start = False
  for line in f :
    line = line.strip()
    if len(line) == 0 :
      continue

    if not start and "WLC_GET_MAGIC" not in line :
      continue
    start = True

    if "define WLC_" not in line :
      continue

    print line

    m = re.search(r"""define\s+(?P<var>\w+)\s+(?P<val>\d+)""", line)
    if m is None :
      print line
      break
    print >>c_file, "\t\"%s\", \t\t/* %s */" % (m.group('var'), m.group('val'))
    if int(m.group('val')) == 319 :
      break

  print >>c_file, "};"
