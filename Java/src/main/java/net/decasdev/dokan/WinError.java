/*
  JDokan : Java library for Dokan

  Copyright (C) 2008 Yu Kobayashi http://yukoba.accelart.jp/

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

/** From WinError.h */
public enum WinError {
	 ERROR_SUCCESS (0),
	 ERROR_INVALID_FUNCTION (1),
	 ERROR_FILE_NOT_FOUND (2),
	 ERROR_PATH_NOT_FOUND (3),
	 ERROR_TOO_MANY_OPEN_FILES (4),
	 ERROR_ACCESS_DENIED (5),
	 ERROR_INVALID_HANDLE (6),
	 ERROR_INVALID_ACCESS (12),
	 ERROR_INVALID_DATA (13),
	 ERROR_INVALID_DRIVE (15),
	 ERROR_WRITE_FAULT (29),
	 ERROR_READ_FAULT (30),
	 ERROR_GEN_FAILURE (31),
	 ERROR_SHARING_VIOLATION (32),
	 ERROR_LOCK_VIOLATION (33),
	 ERROR_HANDLE_EOF (38),
	 ERROR_HANDLE_DISK_FULL (39),
	 ERROR_NOT_SUPPORTED (50),
	 ERROR_FILE_EXISTS (80),
	 ERROR_CANNOT_MAKE (82),
	 ERROR_INVALID_PARAMETER (87),
	 ERROR_DRIVE_LOCKED (108),
	 ERROR_OPEN_FAILED (110),
	 ERROR_BUFFER_OVERFLOW (111),
	 ERROR_DISK_FULL (112),
	 ERROR_INVALID_NAME (123),
	 ERROR_NO_VOLUME_LABEL (125),
	 ERROR_NEGATIVE_SEEK (131),
	 ERROR_SEEK_ON_DEVICE (132),
	 ERROR_DIR_NOT_EMPTY (145),
	 ERROR_LABEL_TOO_LONG (154),
	 ERROR_DISCARDED (157),
	 ERROR_NOT_LOCKED (158),
	 ERROR_BAD_ARGUMENTS (160),
	 ERROR_BAD_PATHNAME (161),
	 ERROR_LOCK_FAILED (167),
	 ERROR_BUSY (170),
	 ERROR_ALREADY_EXISTS (183),
	 ERROR_FILENAME_EXCED_RANGE (206),
	 ERROR_META_EXPANSION_TOO_LONG (208),
	 ERROR_FILE_TOO_LARGE (223),
	 ERROR_VIRUS_INFECTED (225),
	 ERROR_VIRUS_DELETED (226),
	 ERROR_DIRECTORY (267),
	 ERROR_MAX_THRDS_REACHED(164);

    private int value;

    WinError(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
