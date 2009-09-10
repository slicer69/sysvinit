/*
 * set.h	Macros that look like sigaddset et al. but
 *		aren't. They are used to manipulate bits in
 *		an integer, to do our signal bookeeping.
 *
 * Copyright (C) 2005 Miquel van Smoorenburg.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#define ISMEMBER(set, val) ((set) & (1 << (val)))
#define DELSET(set, val)   ((set) &= ~(1 << (val)))
#define ADDSET(set, val)   ((set) |=  (1 << (val)))
#define EMPTYSET(set)      ((set) = 0)

