#!/usr/bin/env python
import getopt, sys
import hashlib
import struct

'''
Author: Andy Dove

$ python vbr_parser.py -f vbr
    no frills, prints out to stdout

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version
2 of the License, or (at your option) any later version.

 Using structures defined in File System Forensic Analysis pg 88+
 boot code is from bytes 0-439 in the partition table
 we should dissassemble
'''


class VBRParser:
    def __init__(self, data, type='NTFS'):
        self.vbr = data
        self.type = type
        self.sha1 = hashlib.sha1(data).hexdigest()
        if type == 'FAT32':
            pass
        elif type == 'FAT16':
            pass
        else:
            self.ParseNTFS()


    def ParseNTFS(self):
        self.JI = 'JMP 0x%x' % (ord(self.vbr[0x01]) + 2)
        self.OEM = self.vbr[0x03:0x0B]
        self.BPB = self.parse_bpb(self.vbr)
        self.BootStrapCode = self.vbr[0x54:0x01FE]
        self.BSC_sha1 = hashlib.sha1(self.vbr).hexdigest()
        self.EOS = self.vbr[0x01FE:].encode('hex')

    def parse_bpb(self,data):
        if self.type == 'NTFS':
            bpb = []
            bpb.append(('Bytes Per Sector', str(struct.unpack('<h', data[0x0b:0x0d])[0])))
            bpb.append(('Sectors Per Cluster', str(ord(data[0x0d]))))
            bpb.append(('Media Descriptor', "0x%x" % ord(data[0x15])))
            bpb.append(('Sectors Per Track', str(struct.unpack('<h', data[0x18:0x1a])[0])))
            bpb.append(('Number of Heads', str(struct.unpack('<h', data[0x1a:0x1c])[0])))
            bpb.append(('Hidden Sectors', str(struct.unpack('<i', data[0x1c:0x20])[0])))
            bpb.append(('Total Sectors', str(struct.unpack('<q', data[0x28:0x30])[0])))
            bpb.append(('$MFT Cluster', str(struct.unpack('<q', data[0x30:0x38])[0])))
            bpb.append(('$MFTmirr Cluster', str(struct.unpack('<q', data[0x38:0x40])[0])))
            bpb.append(('Clusters Per File Record Segment', str(struct.unpack('<i', data[0x40:0x44])[0])))
            bpb.append(('Clusters Per Index Buffer', str(ord(data[0x44]))))
            bpb.append(('Volume Serial Number (bytes)', data[0x48:0x50].encode('hex')))
            bpb.append(('Volume Serial Number (int)', str(struct.unpack('<q', data[0x48:0x50])[0])))
            bpb.append(('Volume Serial Number (hex)', '0x%x' % struct.unpack('<q', data[0x48:0x50])[0]))
            bpb.append(('Checksum (not in NTFS)', '0x%x' % struct.unpack('<i', data[0x50:0x54])[0]))

            return bpb
        else:
            return self.Hexdump(data[0x0B:0x54])

    def print_self(self):
        print '\n' + ' General '.center(70, '=')
        print 'SHA1:                %s' % self.sha1
        print 'Jump Instruction:    %s' % self.JI
        print 'OEM ID:              %s' % self.OEM
        print 'EOS Marker:          %s' % self.EOS
        print '\n' + ' BPB '.center(70,'=')
        if self.type in ('NTFS'):
            for entry in self.BPB:
                print (entry[0] + ':').ljust(24) + entry[1]
        else:
            for line in self.BPB:
                print '%04d %s %s' % (int(line[0]), ''.join(line[2]).ljust(16) , line[1])
        print '\n' + ' Boot Strap '.center(70,'=')
        print 'SHA1:                %s\n' % self.BSC_sha1
        for line in self.Hexdump(self.BootStrapCode):
            print '%04d %s %s' % (int(line[0]), ''.join(line[2]).ljust(16), line[1])




    def Hexdump(self, data, given_offset = 0, width = 16):
        for offset in xrange(0, len(data), width):
            row_data = data[offset:offset + width]
            translated_data = [x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
            hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

            yield offset + given_offset, hexdata, translated_data


def usage():
    print "boot_parser.py:\n"
    print " -f <boot_sector_file>"

def main():
    file = None
    output = sys.stdout
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:", ["help", "file="])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif o in ("-f", "--file"):
            file = open(a,'rb')
        else:
            assert False, "unhandled option\n\n"
            sys.exit(2)

    if file == None:
        usage()
        return

    data = file.read(512)
    if len(data) == 512:
        myVBR = VBRParser(data)
    else:
        print "Boot sector file too small"
        return

    myVBR.print_self()

if __name__ == "__main__":
    main()