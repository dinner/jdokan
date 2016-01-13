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

public enum CreationDisposition {
	FILE_SUPERSEDE(0),
    FILE_OPEN(1),
    FILE_CREATE(2),
    FILE_OPEN_IF(3),
    FILE_OVERWRITE(4),
    FILE_OVERWRITE_IF(5),
    UNDEFINED(-1);

    private int value;

    CreationDisposition(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static CreationDisposition build(int value) {
        for ( CreationDisposition current : values() ) {
            if ( current.getValue() == value ) {
                return current;
            }
        }
        return UNDEFINED;
    }


}
