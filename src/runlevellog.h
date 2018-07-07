/*
 * runlevellog  - Saves and restores runlevel from distor-neutral location.
 *
 *
 *              This file is part of the sysvinit suite,
 *              Copyright (C) 2018 Jesse Smith
 *
 *              This program is free software; you can redistribute it and/or modify
 *              it under the terms of the GNU General Public License as published by
 *              the Free Software Foundation; version 2 of the License.
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *              GNU General Public License for more details.
 *
 *              You should have received a copy of the GNU General Public License
 *              along with this program; if not, write to the Free Software
 *              Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef RUNLEVEL_LOG_HEADER__
#define RUNLEVEL_LOG_HEADER__

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

int Write_Runlevel_Log(int new_runlevel);
int Read_Runlevel_Log(int *runlevel);

#endif

