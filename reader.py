import sys
import os
import struct
import mbr_parser

class BootRecordCollector(object):

    def __init__(self):
        self.description = 'Boot Record Collector'

    def OpenDisk(self,path):
        try:
            self.rd = open(path, 'rb+')
        except (IOError, TypeError):
            print 'Unable to open %s.' % path
            sys.exit()

    def get_mbr(self):
        data = self.rd.read(512)
        if len(data) == 512:
            myMBR = mbr_parser.MBRParser(data)
        elif len(data) == 440:
            myMBR = mbr_parser.MBRParser(data, True)
        else:
            print "MBR file too small"
            return

        lines = myMBR.print_self()
        for l in lines:
            print l

        self.mbr = data

    # BIOS parameter block - http://www.ntfs.com/ntfs-partition-boot-sector.htm
    def get_boot_sector(self):

        part_offset = 2048 * 512  # Offset to first partition = right after LBA
        self.part['start'] = part_offset
        self.rd.seek(self.part['start'])
        data = self.rd.read(512)

        (self.part['bps'], self.part['spc']) = struct.unpack_from('=HB', data, 11)  # bytes/sec, sec/cluster
        mftcluster = struct.unpack_from('=Q', data, 48)  # Offset to $MFT in clusters

        # MFT cluster offset * (sectors per cluster * bytes per sector) + start of partition
        # This is hardwired, but if the partition isn't the first one, this'll break
        self.part['mftstart'] = mftcluster[0] * self.part['bps'] * self.part['spc'] + part_offset

if __name__ == '__main__':
    collector = BootRecordCollector()
    collector.OpenDisk(r'\\.\PhysicalDrive0')

