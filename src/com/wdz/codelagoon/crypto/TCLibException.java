package com.wdz.codelagoon.crypto;

/*
TruPax  Copyright (C) 2015  CODERSLAGOON

TruPax is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

TruPax is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
TruPax. If not, see http://www.gnu.org/licenses/.

*/

public class TCLibException extends Exception {
	public TCLibException() {
		super();
	}

	public TCLibException(String message) {
		super(message);
	}

	public TCLibException(Throwable cause) {
		super(cause);
	}

	private static final long serialVersionUID = 113929922920725296L;
}
