/*
 * Copyright (C) 1998,1999 Nikos Mavroyanopoulos
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/* $Id$ */

#ifndef LIBDEFS_H
# define LIBDEFS_H
# include <libdefs.h>
#endif

#include <bzero.h>
#include <swap.h>
#include <xmemory.h>

#ifndef FAST

word32 rotl(word32 v, word32 cnt)
{
	cnt &= (32 - 1);
	while (cnt--)
		v = ((v << 1) | (v >> (32 - 1)));
	return v;
}
/* rotate right */
word32 rotr(word32 v, word32 cnt)
{
	cnt &= (32 - 1);
	while (cnt--)
		v = ((v >> 1) | (v << (32 - 1)));
	return v;
}

word16 rotl16(word16 v, word16 cnt)
{
	cnt &= (16 - 1);
	while (cnt--)
		v = ((v << 1) | (v >> (16 - 1)));
	return v;
}
/* rotate right */
word16 rotr16(word16 v, word16 cnt)
{
	cnt &= (16 - 1);
	while (cnt--)
		v = ((v >> 1) | (v << (16 - 1)));
	return v;
}

#endif

#ifndef FAST
/* Byte swap a 32bit integer */
word32 byteswap(word32 x)
{
	return ((rotl(x, 8) & 0x00ff00ff) | (rotr(x, 8) & 0xff00ff00));
}


#endif

/* Byte swap a 16bit integer */
word16 byteswap16(word16 x)
{
	return ( (rotl16(x, 8) & 0x00ff) | (rotr16(x, 8) & 0xff00) );
}
