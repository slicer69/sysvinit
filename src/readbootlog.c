#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bootlogd.h"

#ifndef MAX_LINE
#define MAX_LINE 256
#endif

void print_usage()
{
   printf("readbootlog reads the system's boot log, stripping away\n");
   printf("control characters to make the log human readable.\n\n");
   printf("Usage for readbootlog: readbootlog [-h] [-f logfile]\n");
   printf("\t\t-h             display this help message\n");
   printf("\t\t-f <logfile>   display a specific boot log file\n");
   printf("\t\t               default is to use %s\n", LOGFILE);
   printf("\n");
}

/*
Clean up the unwanted characters from a line of input.
Cleaned line is passed back in output_line.
Returns TRUE on success or FALSE if we encounter an error.
*/
int Clean_Line(char *source_line, char *output_line)
{
   int source_index = 0, target_index = 0;
   int source_max_index;
   char a_letter;
   int done;
   char *garbage;

   if (! source_line) return FALSE;
   if (! output_line) return FALSE;

   source_max_index = strlen(source_line);
   while (source_index < source_max_index)
   {
       a_letter = source_line[source_index];
       if (a_letter == '^')
       {
          /* skip ahead until we find a valid place to stop */
          done = FALSE;
          while (! done)
          {
              source_index++;
              if (source_index >= source_max_index)
                 done = TRUE;
              else
              {
                 a_letter = source_line[source_index];
                 if ( (a_letter == '.') || (a_letter == ' ') ||
                      (a_letter == '(') || (a_letter == 'd') ||
                      (a_letter == '\n') )
                    done = TRUE;
              }
          }   
       }    /* done found character to scrub */
       else if ( (a_letter == '?') && (source_line[source_index + 1] == '?') &&
                 (source_line[source_index + 2] == '7') )
       {
           source_index += 3;
           output_line[target_index] = ' '; 
           target_index++;
       }
       else if ( (a_letter == '8') && (source_line[source_index + 1] == '?') &&
                 (source_line[source_index + 2] == '?') )
       {
           source_index += 3;
           output_line[target_index] = ']';
           target_index++;
       }
       else
       {
            output_line[target_index] = a_letter;
            target_index++;
            source_index++;
       }     /* found valid character */
   }   /* done processing line   */

   garbage = strstr(output_line, " .\n");
   if (garbage)
   {
      garbage[0] = '\n';
      garbage[1] = '\0';
   }
   return TRUE;
}


int main(int argc, char *argv[])
{
  FILE *log_file = NULL;
  char *log_filename = LOGFILE;
  char line[MAX_LINE];
  char output[MAX_LINE];
  char *status;
  int c;

  /* check provided options */
  while ( (c = getopt(argc, argv, "hf:") ) != EOF)
  {
      switch (c)
      {
         case 'h':
               print_usage();
               exit(0);
         case 'f':
              log_filename = optarg;
              break;      
         default:
              print_usage();
              exit(1);
      }
  }   /* done processing arguments */

  log_file = fopen(log_filename, "r");
  if (log_file)
  {
     status = fgets(line, MAX_LINE, log_file);
     while (status)
     {
          memset(output, '\0', MAX_LINE);
          if ( Clean_Line(line, output) )
          {
              printf("%s", output);
          }
          status = fgets(line, MAX_LINE, log_file);
     }    /* done reading file lines */
     fclose(log_file);
  }    /* end of successfully opened log file */
  else
  {
      fprintf(stderr, "Unable to open file %s\n", log_filename);
      return 1;
  }

  return 0;
}
