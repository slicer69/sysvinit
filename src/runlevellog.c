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

#include <stdio.h>
#include "paths.h"
#include "runlevellog.h"

/*
Write the current runlevel to its log file.
The function returns TRUE on success and FALSE
on failure.
*/
int Write_Runlevel_Log(int new_runlevel)
{
   FILE *log_file;
   int status;

   log_file = fopen(RUNLEVEL_LOG, "w");
   if (! log_file)
      return FALSE;

   status = fprintf(log_file, "%c", new_runlevel);
   fclose(log_file);
   if (status < 1)
      return FALSE;
   return TRUE;
}


/*
This function reads the last runlevel from the log file.
The function stores the read value at the addressed passed
into the function (aka runlevel). The function returns
TRUE on success and FALSE on failure.
*/
int Read_Runlevel_Log(int *runlevel)
{
   FILE *log_file;
   int status;

   log_file = fopen(RUNLEVEL_LOG, "r");
   if (! log_file)
     return FALSE;

   status = fscanf(log_file, "%c", (char *) runlevel);
   fclose(log_file);
   if (status < 1)
      return FALSE;
   return TRUE;

}

