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

public class DokanFileInfo {
	public long dokanContext;
	public long handle;
	/** process id for the thread that originally requested a given I/O operation */
	public int processId;
	/** requesting a directory file */
	public boolean isDirectory;
	public boolean deleteOnClose;
	public boolean writeToEndOfFile;
	public boolean synchronousIo;
	public boolean noCache;

	public DokanFileInfo(long handle, int processId, boolean isDirectory,long dokanContext,boolean deleteOnClose, boolean writeToEndOfFile,boolean synchronousIo,boolean noCache) {
		this.handle = handle;
		this.processId = processId;
		this.isDirectory = isDirectory;
		this.dokanContext = dokanContext;
		this.deleteOnClose = deleteOnClose;
		this.writeToEndOfFile = writeToEndOfFile;
		this.synchronousIo = synchronousIo;
		this.noCache = noCache;
		
	}

	@Override public String toString() {
		return "DokanFileInfo(" + "handle=" + handle + "," + "processId=" + processId + ","
				+ "isDirectory=" + isDirectory + ")";
	}
}
