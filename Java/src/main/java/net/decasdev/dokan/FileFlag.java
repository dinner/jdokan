/*
  JDokan : Java library for Dokan
  
  Copyright (C) 2008 Yu Kobayashi http://yukoba.accelart.jp/
  				2009 Caleido AG   http://www.wuala.com/

  http://decas-dev.net/en

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.
*/

package net.decasdev.dokan;

import java.util.EnumSet;
import java.util.Set;

public class FileFlag {
	
    public enum FileFlags {
    	FILE_DIRECTORY_FILE (0x00000001),
    	FILE_WRITE_THROUGH (0x00000002),
    	FILE_SEQUENTIAL_ONLY (0x00000004),
    	 FILE_NO_INTERMEDIATE_BUFFERING  (0x00000008),
    	 FILE_SYNCHRONOUS_IO_ALERT (0x00000010),
         FILE_SYNCHRONOUS_IO_NONALERT (0x00000020),
         FILE_NON_DIRECTORY_FILE (0x00000040),
         FILE_CREATE_TREE_CONNECTION(0x00000080), 
         FILE_COMPLETE_IF_OPLOCKED (0x00000100),
         FILE_NO_EA_KNOWLEDGE(0x00000200),
         FILE_OPEN_REMOTE_INSTANCE(0x00000400),
         FILE_RANDOM_ACCESS (0x00000800),
         FILE_DELETE_ON_CLOSE (0x00001000),
         FILE_OPEN_BY_FILE_ID (0x00002000),
         FILE_OPEN_FOR_BACKUP_INTENT (0x00004000),
         FILE_NO_COMPRESSION (0x00008000),
         FILE_OPEN_REQUIRING_OPLOCK (0x00010000),
         FILE_DISALLOW_EXCLUSIVE (0x00020000),
         FILE_FLAG_SESSION_AWARE(0x00800000),
         FILE_RESERVE_OPFILTER (0x00100000),
         FILE_OPEN_REPARSE_POINT (0x00200000),
         FILE_OPEN_NO_RECALL (0x00400000),
         FILE_OPEN_FOR_FREE_SPACE_QUERY(0x00800000),
    	FILE_FLAG_BACKUP_SEMANTICS(0x02000000);
        
        
        
        ;

        private int value;

        FileFlags(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }


    /**
     * Translates a numeric status code into a Set of StatusFlag enums
     * @param value
     * @return EnumSet representing a documents status
     */
    public static EnumSet<FileFlags> getFlags(int value)
    {
        EnumSet<FileFlags> flags = EnumSet.noneOf(FileFlags.class);

        for (FileFlags flag: FileFlags.values()) {
            long flagValue = flag.getValue();
            if ((flagValue & value) == flagValue)
                flags.add(flag);
        }

        return flags;
    }


    /**
     * Translates a set of flags enums into a numeric status code
     * @param flags if statusFlags
     * @return numeric representation of the document status
     */
    public static long getStatusValue(Set<FileFlags> flags)
    {
        long value=0;
        for (FileFlags flag: flags) {
            value |= flag.getValue();
        }
        return value;
    }

    public static String toString(int value) {
        String result = new String("");
        Set<FileFlags> flags = getFlags(value);

        for (FileFlags flag: flags) {
            result += flag.toString()+ " | ";
        }

        return result;
    }
}
